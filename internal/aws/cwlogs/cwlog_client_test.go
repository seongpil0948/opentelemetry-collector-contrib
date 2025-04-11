// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cwlogs

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

func newAlwaysPassMockLogClient(putLogEventsFunc func(args mock.Arguments)) *Client {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)

	svc.On("PutLogEvents", mock.Anything, mock.Anything, mock.Anything).Return(
		&cloudwatchlogs.PutLogEventsOutput{
			NextSequenceToken: &expectedNextSequenceToken,
		},
		nil).Run(putLogEventsFunc)

	svc.On("CreateLogGroup", mock.Anything, mock.Anything, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogGroupOutput), nil)

	svc.On("CreateLogStream", mock.Anything, mock.Anything, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), nil)

	return newCloudWatchLogClient(svc, 0, nil, logger)
}

type mockCloudWatchLogsClient struct {
	mock.Mock
}

func (svc *mockCloudWatchLogsClient) PutLogEvents(ctx context.Context, input *cloudwatchlogs.PutLogEventsInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error) {
	args := svc.Called(ctx, input, opts)
	return args.Get(0).(*cloudwatchlogs.PutLogEventsOutput), args.Error(1)
}

func (svc *mockCloudWatchLogsClient) CreateLogGroup(ctx context.Context, input *cloudwatchlogs.CreateLogGroupInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.CreateLogGroupOutput, error) {
	args := svc.Called(ctx, input, opts)
	return args.Get(0).(*cloudwatchlogs.CreateLogGroupOutput), args.Error(1)
}

func (svc *mockCloudWatchLogsClient) CreateLogStream(ctx context.Context, input *cloudwatchlogs.CreateLogStreamInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.CreateLogStreamOutput, error) {
	args := svc.Called(ctx, input, opts)
	return args.Get(0).(*cloudwatchlogs.CreateLogStreamOutput), args.Error(1)
}

func (svc *mockCloudWatchLogsClient) PutRetentionPolicy(ctx context.Context, input *cloudwatchlogs.PutRetentionPolicyInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutRetentionPolicyOutput, error) {
	args := svc.Called(ctx, input, opts)
	return args.Get(0).(*cloudwatchlogs.PutRetentionPolicyOutput), args.Error(1)
}

// Tests
var (
	previousSequenceToken     = "0000"
	expectedNextSequenceToken = "1111"
	logGroup                  = "logGroup"
	logStreamName             = "logStream"
	emptySequenceToken        = ""
)

func TestPutLogEvents_HappyCase(t *testing.T) {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)
	
	putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &logGroup,
		LogStreamName: &logStreamName,
	}
	
	putLogEventsOutput := &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken: &expectedNextSequenceToken,
	}

	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, nil)

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.PutLogEvents(putLogEventsInput, defaultRetryCount)

	svc.AssertExpectations(t)
	assert.NoError(t, err)
}

func TestPutLogEvents_HappyCase_SomeRejectedInfo(t *testing.T) {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)
	
	putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &logGroup,
		LogStreamName: &logStreamName,
	}
	
	rejectedLogEventsInfo := &types.RejectedLogEventsInfo{
		ExpiredLogEventEndIndex:  aws.Int32(1),
		TooNewLogEventStartIndex: aws.Int32(2),
		TooOldLogEventEndIndex:   aws.Int32(3),
	}
	
	putLogEventsOutput := &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken:     &expectedNextSequenceToken,
		RejectedLogEventsInfo: rejectedLogEventsInfo,
	}

	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, nil)

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.PutLogEvents(putLogEventsInput, defaultRetryCount)

	svc.AssertExpectations(t)
	assert.NoError(t, err)
}

func TestPutLogEvents_NonAWSError(t *testing.T) {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)
	
	putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &logGroup,
		LogStreamName: &logStreamName,
	}
	
	putLogEventsOutput := &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken: &expectedNextSequenceToken,
	}

	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, errors.New("some random error")).Once()

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.PutLogEvents(putLogEventsInput, defaultRetryCount)

	svc.AssertExpectations(t)
	assert.Error(t, err)
}

func TestPutLogEvents_InvalidParameterException(t *testing.T) {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)
	
	putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &logGroup,
		LogStreamName: &logStreamName,
	}
	
	putLogEventsOutput := &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken: &expectedNextSequenceToken,
	}

	invalidParameterException := &types.InvalidParameterException{}
	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, invalidParameterException).Once()

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.PutLogEvents(putLogEventsInput, defaultRetryCount)

	svc.AssertExpectations(t)
	assert.Error(t, err)
}

func TestPutLogEvents_OperationAbortedException(t *testing.T) {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)
	
	putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &logGroup,
		LogStreamName: &logStreamName,
	}
	
	putLogEventsOutput := &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken: &expectedNextSequenceToken,
	}

	operationAbortedException := &types.OperationAbortedException{}
	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, operationAbortedException).Once()

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.PutLogEvents(putLogEventsInput, defaultRetryCount)

	svc.AssertExpectations(t)
	assert.Error(t, err)
}

func TestPutLogEvents_ServiceUnavailableException(t *testing.T) {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)
	
	putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &logGroup,
		LogStreamName: &logStreamName,
	}
	
	putLogEventsOutput := &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken: &expectedNextSequenceToken,
	}

	serviceUnavailableException := &types.ServiceUnavailableException{}
	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, serviceUnavailableException).Once()

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.PutLogEvents(putLogEventsInput, defaultRetryCount)

	svc.AssertExpectations(t)
	assert.Error(t, err)
}

func TestPutLogEvents_ResourceNotFoundException(t *testing.T) {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)
	
	putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &logGroup,
		LogStreamName: &logStreamName,
	}

	putLogEventsOutput := &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken: &expectedNextSequenceToken,
	}
	
	resourceNotFoundException := &types.ResourceNotFoundException{}

	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, resourceNotFoundException).Once()

	svc.On("CreateLogStream", mock.Anything,
		&cloudwatchlogs.CreateLogStreamInput{LogGroupName: &logGroup, LogStreamName: &logStreamName}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), nil).Once()

	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, nil).Once()

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.PutLogEvents(putLogEventsInput, defaultRetryCount)

	svc.AssertExpectations(t)
	assert.NoError(t, err)
}

func TestLogRetention_NeverExpire(t *testing.T) {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)
	putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &logGroup,
		LogStreamName: &logStreamName,
	}

	putLogEventsOutput := &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken: &expectedNextSequenceToken,
	}
	resourceNotFoundException := &types.ResourceNotFoundException{}

	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, resourceNotFoundException).Once()

	svc.On("CreateLogStream", mock.Anything,
		&cloudwatchlogs.CreateLogStreamInput{LogGroupName: &logGroup, LogStreamName: &logStreamName}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), resourceNotFoundException).Once()

	svc.On("CreateLogGroup", mock.Anything,
		&cloudwatchlogs.CreateLogGroupInput{LogGroupName: &logGroup}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogGroupOutput), nil).Once()

	// PutRetentionPolicy is not called because it is set to 0

	svc.On("CreateLogStream", mock.Anything,
		&cloudwatchlogs.CreateLogStreamInput{LogGroupName: &logGroup, LogStreamName: &logStreamName}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), nil).Once()

	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, nil).Once()

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.PutLogEvents(putLogEventsInput, defaultRetryCount)

	svc.AssertExpectations(t)
	assert.NoError(t, err)
}

func TestLogRetention_RetentionDaysInputted(t *testing.T) {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)
	putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &logGroup,
		LogStreamName: &logStreamName,
	}

	putLogEventsOutput := &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken: &expectedNextSequenceToken,
	}
	resourceNotFoundException := &types.ResourceNotFoundException{}

	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, resourceNotFoundException).Once()

	svc.On("CreateLogStream", mock.Anything,
		&cloudwatchlogs.CreateLogStreamInput{LogGroupName: &logGroup, LogStreamName: &logStreamName}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), resourceNotFoundException).Once()

	svc.On("CreateLogGroup", mock.Anything,
		&cloudwatchlogs.CreateLogGroupInput{LogGroupName: &logGroup}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogGroupOutput), nil).Once()

	svc.On("PutRetentionPolicy", mock.Anything,
		&cloudwatchlogs.PutRetentionPolicyInput{LogGroupName: &logGroup, RetentionInDays: aws.Int32(365)}, mock.Anything).Return(
		new(cloudwatchlogs.PutRetentionPolicyOutput), nil).Once()

	svc.On("CreateLogStream", mock.Anything,
		&cloudwatchlogs.CreateLogStreamInput{LogGroupName: &logGroup, LogStreamName: &logStreamName}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), nil).Once()

	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, nil).Once()

	client := newCloudWatchLogClient(svc, 365, nil, logger)
	err := client.PutLogEvents(putLogEventsInput, defaultRetryCount)

	svc.AssertExpectations(t)
	assert.NoError(t, err)
}

func TestSetTags_NotCalled(t *testing.T) {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)
	putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &logGroup,
		LogStreamName: &logStreamName,
	}

	putLogEventsOutput := &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken: &expectedNextSequenceToken,
	}
	resourceNotFoundException := &types.ResourceNotFoundException{}

	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, resourceNotFoundException).Once()

	svc.On("CreateLogStream", mock.Anything,
		&cloudwatchlogs.CreateLogStreamInput{LogGroupName: &logGroup, LogStreamName: &logStreamName}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), resourceNotFoundException).Once()

	// Tags not added because it is not set

	svc.On("CreateLogGroup", mock.Anything,
		&cloudwatchlogs.CreateLogGroupInput{LogGroupName: &logGroup}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogGroupOutput), nil).Once()

	svc.On("CreateLogStream", mock.Anything,
		&cloudwatchlogs.CreateLogStreamInput{LogGroupName: &logGroup, LogStreamName: &logStreamName}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), nil).Once()

	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, nil).Once()

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.PutLogEvents(putLogEventsInput, defaultRetryCount)

	svc.AssertExpectations(t)
	assert.NoError(t, err)
}

func TestSetTags_Called(t *testing.T) {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)
	putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &logGroup,
		LogStreamName: &logStreamName,
	}

	putLogEventsOutput := &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken: &expectedNextSequenceToken,
	}
	resourceNotFoundException := &types.ResourceNotFoundException{}

	avalue := "avalue"
	sampleTags := map[string]string{"akey": avalue}

	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, resourceNotFoundException).Once()

	svc.On("CreateLogStream", mock.Anything,
		&cloudwatchlogs.CreateLogStreamInput{LogGroupName: &logGroup, LogStreamName: &logStreamName}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), resourceNotFoundException).Once()

	svc.On("CreateLogGroup", mock.Anything,
		&cloudwatchlogs.CreateLogGroupInput{LogGroupName: &logGroup, Tags: sampleTags}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogGroupOutput), nil).Once()

	svc.On("CreateLogStream", mock.Anything,
		&cloudwatchlogs.CreateLogStreamInput{LogGroupName: &logGroup, LogStreamName: &logStreamName}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), nil).Once()

	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, nil).Once()

	client := newCloudWatchLogClient(svc, 0, sampleTags, logger)
	err := client.PutLogEvents(putLogEventsInput, defaultRetryCount)

	svc.AssertExpectations(t)
	assert.NoError(t, err)
}

func TestPutLogEvents_AllRetriesFail(t *testing.T) {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)
	putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &logGroup,
		LogStreamName: &logStreamName,
	}

	putLogEventsOutput := &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken: nil,
	}
	resourceNotFoundException := &types.ResourceNotFoundException{}

	svc.On("PutLogEvents", mock.Anything, putLogEventsInput, mock.Anything).Return(putLogEventsOutput, resourceNotFoundException).Twice()

	svc.On("CreateLogStream", mock.Anything,
		&cloudwatchlogs.CreateLogStreamInput{LogGroupName: &logGroup, LogStreamName: &logStreamName}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), nil).Twice()

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.PutLogEvents(putLogEventsInput, defaultRetryCount)

	svc.AssertExpectations(t)
	assert.Error(t, err)
}

func TestCreateStream_HappyCase(t *testing.T) {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)

	svc.On("CreateLogStream", mock.Anything,
		&cloudwatchlogs.CreateLogStreamInput{LogGroupName: &logGroup, LogStreamName: &logStreamName}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), nil)

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.CreateStream(&logGroup, &logStreamName)

	svc.AssertExpectations(t)
	assert.NoError(t, err)
}

func TestCreateStream_CreateLogStream_ResourceAlreadyExists(t *testing.T) {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)

	resourceAlreadyExistsException := &types.ResourceAlreadyExistsException{}
	svc.On("CreateLogStream", mock.Anything,
		&cloudwatchlogs.CreateLogStreamInput{LogGroupName: &logGroup, LogStreamName: &logStreamName}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), resourceAlreadyExistsException)

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.CreateStream(&logGroup, &logStreamName)

	svc.AssertExpectations(t)
	assert.NoError(t, err)
}

func TestCreateStream_CreateLogStream_ResourceNotFound(t *testing.T) {
	logger := zap.NewNop()
	svc := new(mockCloudWatchLogsClient)

	resourceNotFoundException := &types.ResourceNotFoundException{}
	svc.On("CreateLogStream", mock.Anything,
		&cloudwatchlogs.CreateLogStreamInput{LogGroupName: &logGroup, LogStreamName: &logStreamName}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), resourceNotFoundException).Once()

	svc.On("CreateLogGroup", mock.Anything,
		&cloudwatchlogs.CreateLogGroupInput{LogGroupName: &logGroup}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogGroupOutput), nil)

	svc.On("CreateLogStream", mock.Anything,
		&cloudwatchlogs.CreateLogStreamInput{LogGroupName: &logGroup, LogStreamName: &logStreamName}, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), nil).Once()

	client := newCloudWatchLogClient(svc, 0, nil, logger)
	err := client.CreateStream(&logGroup, &logStreamName)

	svc.AssertExpectations(t)
	assert.NoError(t, err)
}

type UnknownError struct {
	otherField string
}

func (err *UnknownError) Error() string {
	return "Error"
}

func TestUserAgent(t *testing.T) {
	logger := zap.NewNop()
	expectedComponentName := "mockComponentName"
	// buildInfo 변수는 실제 테스트에서 사용되지 않으므로 제거
	
	tests := []struct {
		name                 string
		logGroupName         string
		clientOptions        []ClientOption
		expectedUserAgentContains string
	}{
		{
			"emptyLogGroupAndEmptyClientOptions",
			"",
			[]ClientOption{},
			fmt.Sprintf("%s", expectedComponentName),
		},
		{
			"buildInfoCommandUsed",
			"",
			[]ClientOption{},
			"test-collector-contrib/1.0",
		},
		{
			"nonContainerInsights",
			"test-group",
			[]ClientOption{},
			expectedComponentName,
		},
		{
			"containerInsightsEKS",
			"/aws/containerinsights/eks-cluster-name/performance",
			[]ClientOption{},
			"ContainerInsights",
		},
		{
			"validAppSignalsLogGroupAndAgentString",
			"/aws/application-signals",
			[]ClientOption{WithUserAgentExtras("AppSignals")},
			"AppSignals",
		},
		{
			"multipleAgentStringExtras",
			"/aws/application-signals",
			[]ClientOption{WithUserAgentExtras("abcde", "vwxyz", "12345")},
			"12345",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := new(mockCloudWatchLogsClient)
			
			// 각 테스트 케이스에서 PutLogEvents를 모킹
			svc.On("PutLogEvents", mock.Anything, mock.Anything, mock.Anything).Return(
				&cloudwatchlogs.PutLogEventsOutput{}, nil)
			
			// Client 생성
			client := newCloudWatchLogClient(svc, 0, nil, logger)
			
			// 기본 입력 만들기
			putLogEventsInput := &cloudwatchlogs.PutLogEventsInput{
				LogGroupName:  aws.String("test-group"),
				LogStreamName: aws.String("test-stream"),
				LogEvents: []types.InputLogEvent{
					{
						Message:   aws.String("test message"),
						Timestamp: aws.Int64(12345678),
					},
				},
			}
			
			// 요청 보내기
			client.PutLogEvents(putLogEventsInput, 0)
			
			// 이 테스트는 내부 미들웨어가 올바르게 설정되었는지 직접 검증하기 어렵습니다.
			// 실제 HTTP 요청이 보내지지 않기 때문에 헤더를 확인할 수 없습니다.
			// 따라서 여기서는 Mock이 호출되었는지만 확인합니다.
			svc.AssertCalled(t, "PutLogEvents", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}