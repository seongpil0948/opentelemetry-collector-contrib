// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/xray"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/awsutil"
)

type mockClient struct {
	mock.Mock
	count *atomic.Int32
}

func (m *mockClient) PutTraceSegments(ctx context.Context, input *xray.PutTraceSegmentsInput, opts ...func(*xray.Options)) (*xray.PutTraceSegmentsOutput, error) {
	args := m.Called(input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*xray.PutTraceSegmentsOutput), args.Error(1)
}

func (m *mockClient) PutTelemetryRecords(ctx context.Context, input *xray.PutTelemetryRecordsInput, opts ...func(*xray.Options)) (*xray.PutTelemetryRecordsOutput, error) {
	args := m.Called(input)
	m.count.Add(1)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*xray.PutTelemetryRecordsOutput), args.Error(1)
}

func TestRotateRace(t *testing.T) {
	client := &mockClient{count: &atomic.Int32{}}
	client.On("PutTelemetryRecords", mock.Anything).Return(nil, nil).Once()
	client.On("PutTelemetryRecords", mock.Anything).Return(nil, errors.New("error"))
	sender := newSender(client, WithInterval(100*time.Millisecond))
	sender.Start()
	defer sender.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		ticker := time.NewTicker(time.Millisecond)
		for {
			select {
			case <-ticker.C:
				sender.RecordSegmentsReceived(1)
				sender.RecordSegmentsSpillover(1)
				sender.RecordSegmentsRejected(1)
			case <-ctx.Done():
				return
			}
		}
	}()
	assert.Eventually(t, func() bool {
		return client.count.Load() >= 2
	}, time.Second, 5*time.Millisecond)
}

func TestIncludeMetadata(t *testing.T) {
	cfg := Config{IncludeMetadata: false}
	
	// AWS SDK v2 사용
	awsCfg, err := config.LoadDefaultConfig(context.Background())
	assert.NoError(t, err)
	
	// EC2 메타데이터 클라이언트 생성
	client := imds.NewFromConfig(awsCfg)
	
	set := &awsutil.AWSSessionSettings{ResourceARN: "session_arn"}
	opts := ToOptions(cfg, client, set)
	assert.Empty(t, opts)
	
	cfg.IncludeMetadata = true
	opts = ToOptions(cfg, client, set)
	sender := newSender(&mockClient{}, opts...)
	
	assert.Equal(t, "", sender.hostname)
	assert.Equal(t, "", sender.instanceID)
	assert.Equal(t, "session_arn", sender.resourceARN)
	
	t.Setenv(envAWSHostname, "env_hostname")
	t.Setenv(envAWSInstanceID, "env_instance_id")
	opts = ToOptions(cfg, client, &awsutil.AWSSessionSettings{})
	sender = newSender(&mockClient{}, opts...)
	
	assert.Equal(t, "env_hostname", sender.hostname)
	assert.Equal(t, "env_instance_id", sender.instanceID)
	assert.Equal(t, "", sender.resourceARN)
	
	cfg.Hostname = "cfg_hostname"
	cfg.InstanceID = "cfg_instance_id"
	cfg.ResourceARN = "cfg_arn"
	opts = ToOptions(cfg, client, &awsutil.AWSSessionSettings{})
	sender = newSender(&mockClient{}, opts...)
	
	assert.Equal(t, "cfg_hostname", sender.hostname)
	assert.Equal(t, "cfg_instance_id", sender.instanceID)
	assert.Equal(t, "cfg_arn", sender.resourceARN)
}

func TestQueueOverflow(t *testing.T) {
	obs, logs := observer.New(zap.DebugLevel)
	client := &mockClient{count: &atomic.Int32{}}
	client.On("PutTelemetryRecords", mock.Anything).Return(nil, nil).Once()
	client.On("PutTelemetryRecords", mock.Anything).Return(nil, errors.New("test"))
	
	sender := newSender(
		client,
		WithLogger(zap.New(obs)),
		WithInterval(time.Millisecond),
		WithQueueSize(20),
		WithBatchSize(5),
	)
	
	// V2로 마이그레이션할 때는 TelemetryRecord 생성 방식이 달라집니다
	for i := 1; i <= 25; i++ {
		sender.RecordSegmentsSent(i)
		sender.enqueue(*sender.Rotate())
	}
	
	// number of dropped records
	assert.Equal(t, 5, logs.Len())
	assert.Len(t, sender.queue, 20)
	
	sender.send()
	// only one batch succeeded
	assert.Len(t, sender.queue, 15)
	
	// verify that sent back of queue
	for _, record := range sender.queue {
		assert.Greater(t, *record.SegmentsSentCount, int32(5))
		assert.LessOrEqual(t, *record.SegmentsSentCount, int32(20))
	}
}