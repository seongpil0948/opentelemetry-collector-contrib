// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cwlogs

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// logEvent Tests
func TestLogEvent_eventPayloadBytes(t *testing.T) {
	testMessage := "test message"
	logEvent := NewEvent(0, testMessage)
	assert.Equal(t, len(testMessage)+perEventHeaderBytes, logEvent.eventPayloadBytes())
}

func TestValidateLogEventWithMutating(t *testing.T) {
	maxEventPayloadBytes = 64

	logEvent := NewEvent(0, "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789")
	logEvent.GeneratedTime = time.Now()
	err := logEvent.Validate(zap.NewNop())
	assert.NoError(t, err)
	assert.Positive(t, *logEvent.InputLogEvent.Timestamp)
	assert.Len(t, *logEvent.InputLogEvent.Message, 64-perEventHeaderBytes)

	logEvent = NewEvent(timestampMs, msg)
	assert.NoError(t, logEvent.Validate(zap.NewNop()))
	assert.Equal(t, maxEventPayloadBytes-perEventHeaderBytes, len(*logEvent.InputLogEvent.Message))
	assert.Equal(t, msg[:maxEventPayloadBytes-perEventHeaderBytes]+truncatedSuffix, *logEvent.InputLogEvent.Message)

	maxEventPayloadBytes = defaultMaxEventPayloadBytes
}

func TestValidateLogEventFailed(t *testing.T) {
	logger := zap.NewNop()
	logEvent := NewEvent(0, "")
	err := logEvent.Validate(logger)
	assert.Error(t, err)
	assert.Equal(t, "empty log event message", err.Error())

	invalidTimestamp := time.Now().AddDate(0, -1, 0)
	logEvent = NewEvent(invalidTimestamp.Unix()*1e3, "test")
	err = logEvent.Validate(logger)
	assert.Error(t, err)
	assert.Equal(t, "the log entry's timestamp is older than 14 days or more than 2 hours in the future", err.Error())
}

// eventBatch Tests
func TestLogEventBatch_timestampWithin24Hours(t *testing.T) {
	minDate := time.Date(2017, time.June, 20, 23, 38, 0, 0, time.Local)
	maxDate := minDate.Add(23 * time.Hour)
	logEventBatch := &eventBatch{
		maxTimestampMs: maxDate.UnixNano() / 1e6,
		minTimestampMs: minDate.UnixNano() / 1e6,
	}

	// less than the min
	target := minDate.Add(-1 * time.Hour)
	assert.True(t, logEventBatch.isActive(aws.Int64(target.UnixNano()/1e6)))

	target = target.Add(-1 * time.Millisecond)
	assert.False(t, logEventBatch.isActive(aws.Int64(target.UnixNano()/1e6)))

	// more than the max
	target = maxDate.Add(1 * time.Hour)
	assert.True(t, logEventBatch.isActive(aws.Int64(target.UnixNano()/1e6)))

	target = target.Add(1 * time.Millisecond)
	assert.False(t, logEventBatch.isActive(aws.Int64(target.UnixNano()/1e6)))

	// in between min and max
	target = minDate.Add(2 * time.Hour)
	assert.True(t, logEventBatch.isActive(aws.Int64(target.UnixNano()/1e6)))
}

func TestLogEventBatch_sortLogEvents(t *testing.T) {
	totalEvents := 10
	logEventBatch := &eventBatch{
		putLogEventsInput: &cloudwatchlogs.PutLogEventsInput{
			LogEvents: make([]types.InputLogEvent, 0, totalEvents),
		},
	}

	for i := 0; i < totalEvents; i++ {
		timestamp := rand.Int()
		logEvent := NewEvent(int64(timestamp), fmt.Sprintf("message%v", timestamp))
		fmt.Printf("logEvents[%d].Timestamp=%d.\n", i, timestamp)
		logEventBatch.putLogEventsInput.LogEvents = append(logEventBatch.putLogEventsInput.LogEvents, logEvent.InputLogEvent)
	}

	logEventBatch.sortLogEvents()

	logEvents := logEventBatch.putLogEventsInput.LogEvents
	for i := 1; i < totalEvents; i++ {
		fmt.Printf("logEvents[%d].Timestamp=%d, logEvents[%d].Timestamp=%d.\n", i-1, *logEvents[i-1].Timestamp, i, *logEvents[i].Timestamp)
		assert.Less(t, *logEvents[i-1].Timestamp, *logEvents[i].Timestamp, "timestamp is not sorted correctly")
	}
}

//
//  pusher Mocks
//

// Need to remove the tmp state folder after testing.
func newMockPusher() *logPusher {
	svc := newAlwaysPassMockLogClient(func(_ mock.Arguments) {})
	return newLogPusher(StreamKey{
		LogGroupName:  logGroup,
		LogStreamName: logStreamName,
	}, svc, zap.NewNop())
}

//
// pusher Tests
//

var (
	timestampMs   = time.Now().UnixNano() / 1e6
	msg           = "test log message"
	logGroup      = "logGroup"
	logStreamName = "logStreamName"
)

func TestPusher_newLogEventBatch(t *testing.T) {
	p := newMockPusher()

	logEventBatch := newEventBatch(StreamKey{
		LogGroupName:  logGroup,
		LogStreamName: logStreamName,
	})
	assert.Equal(t, int64(0), logEventBatch.maxTimestampMs)
	assert.Equal(t, int64(0), logEventBatch.minTimestampMs)
	assert.Equal(t, 0, logEventBatch.byteTotal)
	assert.Empty(t, logEventBatch.putLogEventsInput.LogEvents)
	assert.Equal(t, p.logGroupName, logEventBatch.putLogEventsInput.LogGroupName)
	assert.Equal(t, p.logStreamName, logEventBatch.putLogEventsInput.LogStreamName)
}

func TestPusher_AddLogEntry(t *testing.T) {
	ctx := context.Background()
	p := newLogPusher(StreamKey{
		LogGroupName:  logGroup,
		LogStreamName: logStreamName,
	}, newAlwaysPassMockLogClient(func(_ mock.Arguments) {}), zap.NewNop())

	logEvent := NewEvent(timestampMs, msg)
	err := p.AddLogEntry(ctx, logEvent)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(p.logEventBatch.putLogEventsInput.LogEvents))
	assert.Equal(t, logEvent.InputLogEvent, p.logEventBatch.putLogEventsInput.LogEvents[0])
	assert.Equal(t, logEvent.eventPayloadBytes(), p.logEventBatch.byteTotal)
	assert.Equal(t, timestampMs, p.logEventBatch.maxTimestampMs)
	assert.Equal(t, timestampMs, p.logEventBatch.minTimestampMs)
}

func TestPusher_FlushLogEntries(t *testing.T) {
	ctx := context.Background()
	callCount := 0
	p := newLogPusher(StreamKey{
		LogGroupName:  logGroup,
		LogStreamName: logStreamName,
	}, newAlwaysPassMockLogClient(func(_ mock.Arguments) {
		callCount++
	}), zap.NewNop())

	logEvent := NewEvent(timestampMs, msg)
	err := p.AddLogEntry(ctx, logEvent)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(p.logEventBatch.putLogEventsInput.LogEvents))

	err = p.ForceFlush(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 1, callCount)
	assert.Equal(t, 0, len(p.logEventBatch.putLogEventsInput.LogEvents))
	assert.Equal(t, 0, p.logEventBatch.byteTotal)
	assert.Equal(t, int64(0), p.logEventBatch.maxTimestampMs)
	assert.Equal(t, int64(0), p.logEventBatch.minTimestampMs)
}

func TestStreamManager(t *testing.T) {
	ctx := context.Background()
	svc := new(mockCloudWatchLogsClient)
	svc.On("CreateLogGroup", ctx, mock.Anything, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogGroupOutput), nil)
	svc.On("CreateLogStream", ctx, mock.Anything, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), nil)
	client := newCloudWatchLogClient(svc, 0, nil, zap.NewNop())
	manager := NewLogStreamManager(client)

	streamKey := StreamKey{LogGroupName: "group", LogStreamName: "stream"}
	err := manager.InitStream(ctx, streamKey)
	assert.NoError(t, err)
	svc.AssertCalled(t, "CreateLogGroup", ctx, mock.Anything)
	svc.AssertCalled(t, "CreateLogStream", ctx, mock.Anything)

	// Test existing stream
	svc = new(mockCloudWatchLogsClient)
	svc.On("CreateLogGroup", ctx, mock.Anything, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogGroupOutput), nil)
	svc.On("CreateLogStream", ctx, mock.Anything, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), nil)
	client = newCloudWatchLogClient(svc, 0, nil, zap.NewNop())
	manager = NewLogStreamManager(client)
	manager.(*logStreamManager).streams[streamKey] = true
	err = manager.InitStream(ctx, streamKey)
	assert.NoError(t, err)
	svc.AssertNotCalled(t, "CreateLogGroup", ctx, mock.Anything)
	svc.AssertNotCalled(t, "CreateLogStream", ctx, mock.Anything)

	// Test error case
	svc = new(mockCloudWatchLogsClient)
	expectedErr := errors.New("failed")
	svc.On("CreateLogGroup", ctx, mock.Anything, mock.Anything).Return(nil, expectedErr)
	client = newCloudWatchLogClient(svc, 0, nil, zap.NewNop())
	manager = NewLogStreamManager(client)
	err = manager.InitStream(ctx, StreamKey{LogGroupName: "new-group", LogStreamName: "new-stream"})
	assert.ErrorIs(t, err, expectedErr)
}

func TestMultiStreamFactory(t *testing.T) {
	svc := newAlwaysPassMockLogClient(func(_ mock.Arguments) {})
	logStreamManager := NewLogStreamManager(svc) // Pass svc (*Client) directly
	factory := NewMultiStreamPusherFactory(logStreamManager, svc, nil) // Pass svc (*Client) directly

	pusher := factory.CreateMultiStreamPusher()

	assert.IsType(t, &multiStreamPusher{}, pusher)
}

func TestMultiStreamPusher(t *testing.T) {
	ctx := context.Background()
	callCount := 0
	svc := new(mockCloudWatchLogsClient)
	svc.On("CreateLogGroup", ctx, mock.Anything, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogGroupOutput), nil)
	svc.On("CreateLogStream", ctx, mock.Anything, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), nil)
	svc.On("PutLogEvents", ctx, mock.Anything, mock.Anything).Return(
		&cloudwatchlogs.PutLogEventsOutput{NextSequenceToken: aws.String("token")}, nil).Run(func(_ mock.Arguments) {
		callCount++
	})
	client := newCloudWatchLogClient(svc, 0, nil, zap.NewNop())
	manager := NewLogStreamManager(client)
	pusher := newMultiStreamPusher(manager, client, zap.NewNop())

	stream1 := StreamKey{LogGroupName: "group1", LogStreamName: "stream1"}
	stream2 := StreamKey{LogGroupName: "group2", LogStreamName: "stream2"}

	event1 := NewEvent(time.Now().UnixMilli(), "message1")
	event1.StreamKey = stream1
	event2 := NewEvent(time.Now().UnixMilli(), "message2")
	event2.StreamKey = stream2

	err := pusher.AddLogEntry(ctx, event1)
	assert.NoError(t, err)
	err = pusher.AddLogEntry(ctx, event2)
	assert.NoError(t, err)

	err = pusher.ForceFlush(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 2, callCount)

	callCount = 0
	svc = new(mockCloudWatchLogsClient)
	svc.On("CreateLogGroup", ctx, mock.Anything, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogGroupOutput), nil)
	svc.On("CreateLogStream", ctx, mock.Anything, mock.Anything).Return(
		new(cloudwatchlogs.CreateLogStreamOutput), nil)
	svc.On("PutLogEvents", ctx, mock.Anything, mock.Anything).Return(
		&cloudwatchlogs.PutLogEventsOutput{NextSequenceToken: aws.String("token")}, nil).Run(func(_ mock.Arguments) {
		callCount++
	})
	client = newCloudWatchLogClient(svc, 0, nil, zap.NewNop())
	manager = NewLogStreamManager(client)
	pusher = newMultiStreamPusher(manager, client, zap.NewNop())

	stream3 := StreamKey{LogGroupName: "group3", LogStreamName: "stream3"}
	event3 := NewEvent(time.Now().UnixMilli(), "message3")
	event3.StreamKey = stream3

	err = pusher.AddLogEntry(ctx, event3)
	assert.NoError(t, err)
	err = pusher.ForceFlush(ctx)
	assert.NoError(t, err)
	svc.AssertCalled(t, "CreateLogGroup", ctx, mock.Anything)
	svc.AssertCalled(t, "CreateLogStream", ctx, mock.Anything)
	assert.Equal(t, 1, callCount)
}