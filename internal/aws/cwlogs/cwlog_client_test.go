// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cwlogs

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

//
//  pusher Mocks
//

// mockCloudWatchLogsClient implements cloudWatchClient interface for testing
type mockCloudWatchLogsClient struct {
	mock.Mock
}

func (svc *mockCloudWatchLogsClient) PutLogEvents(ctx context.Context, input *cloudwatchlogs.PutLogEventsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error) {
	args := svc.Called(ctx, input, optFns)
	return args.Get(0).(*cloudwatchlogs.PutLogEventsOutput), args.Error(1)
}

func (svc *mockCloudWatchLogsClient) CreateLogGroup(ctx context.Context, input *cloudwatchlogs.CreateLogGroupInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.CreateLogGroupOutput, error) {
	args := svc.Called(ctx, input, optFns)
	return args.Get(0).(*cloudwatchlogs.CreateLogGroupOutput), args.Error(1)
}

func (svc *mockCloudWatchLogsClient) CreateLogStream(ctx context.Context, input *cloudwatchlogs.CreateLogStreamInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.CreateLogStreamOutput, error) {
	args := svc.Called(ctx, input, optFns)
	return args.Get(0).(*cloudwatchlogs.CreateLogStreamOutput), args.Error(1)
}

func (svc *mockCloudWatchLogsClient) PutRetentionPolicy(ctx context.Context, input *cloudwatchlogs.PutRetentionPolicyInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutRetentionPolicyOutput, error) {
	args := svc.Called(ctx, input, optFns)
	return args.Get(0).(*cloudwatchlogs.PutRetentionPolicyOutput), args.Error(1)
}

func (svc *mockCloudWatchLogsClient) TagResource(ctx context.Context, input *cloudwatchlogs.TagResourceInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.TagResourceOutput, error) {
	args := svc.Called(ctx, input, optFns)
	return args.Get(0).(*cloudwatchlogs.TagResourceOutput), args.Error(1)
}

// Helper function to create a mock client that always passes PutLogEvents
func newAlwaysPassMockLogClient(putLogEventsFunc func(args mock.Arguments)) *Client {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)

	ctx := context.Background()
	expectedNextSequenceToken := "1111"

	svc.On("PutLogEvents", ctx, mock.Anything, mock.Anything).Return(
		&cloudwatchlogs.PutLogEventsOutput{
			NextSequenceToken: &expectedNextSequenceToken,
		},
		nil).Run(putLogEventsFunc)

	svc.On("CreateLogGroup", ctx, mock.Anything, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogGroupOutput), nil)

	svc.On("CreateLogStream", ctx, mock.Anything, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), nil)

	svc.On("TagResource", ctx, mock.Anything, mock.Anything).Return(
		new(cloudwatchlogs.TagResourceOutput), nil)

	svc.On("PutRetentionPolicy", ctx, mock.Anything, mock.Anything).Return(
		new(cloudwatchlogs.PutRetentionPolicyOutput), nil)

	return newCloudWatchLogClient(svc, 0, nil, logger)
}

//
// pusher Tests
//

func TestPutLogEvents_HappyCase(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)

	putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  aws.String("logGroup"),
		LogStreamName: aws.String("logStream"),
	}

	expectedNextSequenceToken := "1111"
	putLogEventsOutput := &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken: &expectedNextSequenceToken,
	}

	svc.On("PutLogEvents", ctx, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, nil)

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.PutLogEvents(ctx, putLogEventsInput, defaultRetryCount)

	svc.AssertExpectations(t)
	assert.NoError(t, err)
}

func TestPutLogEvents_RejectedLogEventsInfo(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)

	putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  aws.String("logGroup"),
		LogStreamName: aws.String("logStream"),
	}

	rejectedLogEventsInfo := &types.RejectedLogEventsInfo{
		ExpiredLogEventEndIndex:  aws.Int32(1),
		TooNewLogEventStartIndex: aws.Int32(2),
		TooOldLogEventEndIndex:   aws.Int32(3),
	}

	expectedNextSequenceToken := "1111"
	putLogEventsOutput := &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken:     &expectedNextSequenceToken,
		RejectedLogEventsInfo: rejectedLogEventsInfo,
	}

	svc.On("PutLogEvents", ctx, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, nil)

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.PutLogEvents(ctx, putLogEventsInput, defaultRetryCount)

	svc.AssertExpectations(t)
	assert.NoError(t, err)
}

func TestPutLogEvents_GeneralError(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)

	putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  aws.String("logGroup"),
		LogStreamName: aws.String("logStream"),
	}

	svc.On("PutLogEvents", ctx, putLogEventsInput, mock.Anything).Return(
		&cloudwatchlogs.PutLogEventsOutput{},
		errors.New("some general error"))

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.PutLogEvents(ctx, putLogEventsInput, defaultRetryCount)

	svc.AssertExpectations(t)
	assert.Error(t, err)
}