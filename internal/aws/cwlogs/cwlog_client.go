// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cwlogs // import "github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/cwlogs"

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"go.opentelemetry.io/collector/component"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/cwlogs/handler"
)

const (
	// this is the retry count, the total attempts will be at most retry count + 1.
	defaultRetryCount          = 1
	errCodeThrottlingException = "ThrottlingException"
)

var containerInsightsRegexPattern = regexp.MustCompile(`^/aws/.*containerinsights/.*/(performance|prometheus)$`)

// CloudWatchLogsClient defines the interface for AWS CloudWatch Logs API operations
type CloudWatchLogsClient interface {
	PutLogEvents(ctx context.Context, params *cloudwatchlogs.PutLogEventsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error)
	CreateLogStream(ctx context.Context, params *cloudwatchlogs.CreateLogStreamInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.CreateLogStreamOutput, error)
	CreateLogGroup(ctx context.Context, params *cloudwatchlogs.CreateLogGroupInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.CreateLogGroupOutput, error)
	PutRetentionPolicy(ctx context.Context, params *cloudwatchlogs.PutRetentionPolicyInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutRetentionPolicyOutput, error)
}

// Client struct for CloudWatch Logs client
type Client struct {
	svc          CloudWatchLogsClient
	logRetention int64
	tags         map[string]string // 올바른 타입 지정
	logger       *zap.Logger
}

type ClientOption func(*cwLogClientConfig)

type cwLogClientConfig struct {
	userAgentExtras []string
}

func WithUserAgentExtras(userAgentExtras ...string) ClientOption {
	return func(config *cwLogClientConfig) {
		config.userAgentExtras = append(config.userAgentExtras, userAgentExtras...)
	}
}

// Create a log client based on the actual cloudwatch logs client.
func newCloudWatchLogClient(svc CloudWatchLogsClient, logRetention int64, tags map[string]string, logger *zap.Logger) *Client {
	logClient := &Client{
		svc:          svc,
		logRetention: logRetention,
		tags:         tags,
		logger:       logger,
	}
	return logClient
}

// NewClient creates a new CloudWatch Logs client
func NewClient(logger *zap.Logger, awsConfig aws.Config, buildInfo component.BuildInfo, logGroupName string, logRetention int64, tags map[string]string, componentName string, opts ...ClientOption) *Client {
	// Create the client with aws configuration
	client := cloudwatchlogs.NewFromConfig(awsConfig)

	// Add structured log handler
	handler.AddStructuredLogHandler(client)

	// Process client options
	option := &cwLogClientConfig{
		userAgentExtras: []string{},
	}
	for _, opt := range opts {
		opt(option)
	}

	// Add user agent handler
	handler.AddUserAgentHandler(client, buildInfo, logGroupName, componentName, option.userAgentExtras)

	return newCloudWatchLogClient(client, logRetention, tags, logger)
}

// PutLogEvents handles different possible errors that could be returned from server side and retries
// if necessary.
func (client *Client) PutLogEvents(input *cloudwatchlogs.PutLogEventsInput, retryCnt int) error {
	ctx := context.Background()
	var response *cloudwatchlogs.PutLogEventsOutput
	var err error

	for i := 0; i <= retryCnt; i++ {
		response, err = client.svc.PutLogEvents(ctx, input)
		if err != nil {
			var resourceNotFoundException *types.ResourceNotFoundException
			if errors.As(err, &resourceNotFoundException) {
				tmpErr := client.CreateStream(input.LogGroupName, input.LogStreamName)
				if tmpErr != nil {
					return tmpErr
				}
				continue
			}

			var operationAbortedException *types.OperationAbortedException
			if errors.As(err, &operationAbortedException) {
				client.logger.Warn("cwlog_client: Error occurs in PutLogEvents, will retry the request", zap.Error(err))
				return err
			}

			var serviceUnavailableException *types.ServiceUnavailableException
			if errors.As(err, &serviceUnavailableException) {
				client.logger.Warn("cwlog_client: Error occurs in PutLogEvents, will retry the request", zap.Error(err))
				return err
			}

			var invalidParameterException *types.InvalidParameterException
			if errors.As(err, &invalidParameterException) {
				client.logger.Error("cwlog_client: Error occurs in PutLogEvents, will not retry the request", 
					zap.Error(err), 
					zap.String("LogGroupName", *input.LogGroupName), 
					zap.String("LogStreamName", *input.LogStreamName))
				return err
			}

			// Check for ThrottlingException which isn't directly available as a type
			if err.Error() == errCodeThrottlingException {
				client.logger.Warn("cwlog_client: Error occurs in PutLogEvents, will not retry the request", 
					zap.Error(err), 
					zap.String("LogGroupName", *input.LogGroupName), 
					zap.String("LogStreamName", *input.LogStreamName))
				return err
			}

			client.logger.Error("cwlog_client: Error occurs in PutLogEvents", zap.Error(err))
			return err
		}

		// TODO: Should have metrics to provide visibility of these failures
		if response != nil {
			if response.RejectedLogEventsInfo != nil {
				rejectedLogEventsInfo := response.RejectedLogEventsInfo
				if rejectedLogEventsInfo.TooOldLogEventEndIndex != nil {
					client.logger.Warn(fmt.Sprintf("%d log events for log group name are too old", *rejectedLogEventsInfo.TooOldLogEventEndIndex), zap.String("LogGroupName", *input.LogGroupName))
				}
				if rejectedLogEventsInfo.TooNewLogEventStartIndex != nil {
					client.logger.Warn(fmt.Sprintf("%d log events for log group name are too new", *rejectedLogEventsInfo.TooNewLogEventStartIndex), zap.String("LogGroupName", *input.LogGroupName))
				}
				if rejectedLogEventsInfo.ExpiredLogEventEndIndex != nil {
					client.logger.Warn(fmt.Sprintf("%d log events for log group name are expired", *rejectedLogEventsInfo.ExpiredLogEventEndIndex), zap.String("LogGroupName", *input.LogGroupName))
				}
			}

			if response.NextSequenceToken != nil {
				break
			}
		}
	}
	if err != nil {
		client.logger.Error("All retries failed for PutLogEvents. Drop this request.", zap.Error(err))
	}
	return err
}

// CreateStream prepares the log group and log stream
func (client *Client) CreateStream(logGroup, streamName *string) error {
	ctx := context.Background()
	// CreateLogStream / CreateLogGroup
	_, err := client.svc.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  logGroup,
		LogStreamName: streamName,
	})
	
	if err != nil {
		client.logger.Debug("cwlog_client: creating stream fail", zap.Error(err))
		var resourceNotFoundException *types.ResourceNotFoundException
		if errors.As(err, &resourceNotFoundException) {
			// Create Log Group with tags if they exist and were specified in the config
			_, err = client.svc.CreateLogGroup(ctx, &cloudwatchlogs.CreateLogGroupInput{
				LogGroupName: logGroup,
				Tags:         client.tags,
			})
			if err == nil {
				// For newly created log groups, set the log retention policy if specified or non-zero
				if client.logRetention != 0 {
					_, err = client.svc.PutRetentionPolicy(ctx, &cloudwatchlogs.PutRetentionPolicyInput{
						LogGroupName:    logGroup,
						RetentionInDays: aws.Int32(int32(client.logRetention)),
					})
					if err != nil {
						var apiErr error
						if errors.As(err, &apiErr) {
							client.logger.Debug("CreateLogStream / CreateLogGroup has errors related to log retention policy.", 
								zap.String("LogGroupName", *logGroup), 
								zap.String("LogStreamName", *streamName), 
								zap.Error(err))
							return err
						}
					}
				}
				_, err = client.svc.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{
					LogGroupName:  logGroup,
					LogStreamName: streamName,
				})
			}
		}
	}

	if err != nil {
		var resourceAlreadyExistsException *types.ResourceAlreadyExistsException
		if errors.As(err, &resourceAlreadyExistsException) {
			return nil
		}
		client.logger.Debug("CreateLogStream / CreateLogGroup has errors.", 
			zap.String("LogGroupName", *logGroup), 
			zap.String("LogStreamName", *streamName), 
			zap.Error(err))
		return err
	}

	// After a log stream is created the token is always empty.
	return nil
}