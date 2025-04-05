// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry // import "github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/xray/telemetry"

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/xray"
	"github.com/aws/aws-sdk-go-v2/service/xray/types"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/awsutil"
	awsxray "github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/xray"
)

const (
	envAWSHostname     = "AWS_HOSTNAME"
	envAWSInstanceID   = "AWS_INSTANCE_ID"
	metadataHostname   = "hostname"
	metadataInstanceID = "instance-id"

	defaultQueueSize = 30
	defaultBatchSize = 10
	defaultInterval  = time.Minute
)

// Sender wraps a Recorder and periodically sends the records.
type Sender interface {
	Recorder
	// Start send loop.
	Start()
	// Stop send loop.
	Stop()
}

type telemetrySender struct {
	// Recorder is the recorder wrapped by the sender.
	Recorder

	// logger is used to log dropped records.
	logger *zap.Logger
	// client is used to send the records.
	client awsxray.XRayClient

	resourceARN string
	instanceID  string
	hostname    string
	// interval is the amount of time between record rotation and sending attempts.
	interval time.Duration
	// queueSize is the capacity of the queue.
	queueSize int
	// batchSize is the max number of records sent in one request.
	batchSize int

	// queue is used to keep records that failed to send for retry during
	// the next period.
	queue []types.TelemetryRecord

	startOnce sync.Once
	stopWait  sync.WaitGroup
	stopOnce  sync.Once
	// stopCh is the channel used to stop the loop.
	stopCh chan struct{}
}

type Option interface {
	apply(ts *telemetrySender)
}

type optionFunc func(ts *telemetrySender)

func (o optionFunc) apply(ts *telemetrySender) {
	o(ts)
}

func WithResourceARN(resourceARN string) Option {
	return optionFunc(func(ts *telemetrySender) {
		ts.resourceARN = resourceARN
	})
}

func WithInstanceID(instanceID string) Option {
	return optionFunc(func(ts *telemetrySender) {
		ts.instanceID = instanceID
	})
}

func WithHostname(hostname string) Option {
	return optionFunc(func(ts *telemetrySender) {
		ts.hostname = hostname
	})
}

func WithLogger(logger *zap.Logger) Option {
	return optionFunc(func(ts *telemetrySender) {
		ts.logger = logger
	})
}

func WithInterval(interval time.Duration) Option {
	return optionFunc(func(ts *telemetrySender) {
		ts.interval = interval
	})
}

func WithQueueSize(queueSize int) Option {
	return optionFunc(func(ts *telemetrySender) {
		ts.queueSize = queueSize
	})
}

func WithBatchSize(batchSize int) Option {
	return optionFunc(func(ts *telemetrySender) {
		ts.batchSize = batchSize
	})
}

type metadataProvider interface {
	get() string
}

func getMetadata(providers ...metadataProvider) string {
	var metadata string
	for _, provider := range providers {
		if metadata = provider.get(); metadata != "" {
			break
		}
	}
	return metadata
}

type simpleMetadataProvider struct {
	metadata string
}

func (p simpleMetadataProvider) get() string {
	return p.metadata
}

type envMetadataProvider struct {
	envKey string
}

func (p envMetadataProvider) get() string {
	return os.Getenv(p.envKey)
}

type ec2MetadataProvider struct {
	client     *imds.Client
	metadataKey string
}

func (p ec2MetadataProvider) get() string {
	ctx := context.Background()
	var metadata string
	if result, err := p.client.GetMetadata(ctx, &imds.GetMetadataInput{Path: p.metadataKey}); err == nil {
		// io.ReadCloser를 문자열로 변환
		if content, err := io.ReadAll(result.Content); err == nil {
			metadata = string(content)
		}
		result.Content.Close()
	}
	return metadata
}

// ToOptions returns the metadata options if enabled by the config.
func ToOptions(cfg Config, client *imds.Client, settings *awsutil.AWSSessionSettings) []Option {
	if !cfg.IncludeMetadata {
		return nil
	}
	
	return []Option{
		WithHostname(getMetadata(
			simpleMetadataProvider{metadata: cfg.Hostname},
			envMetadataProvider{envKey: envAWSHostname},
			ec2MetadataProvider{client: client, metadataKey: metadataHostname},
		)),
		WithInstanceID(getMetadata(
			simpleMetadataProvider{metadata: cfg.InstanceID},
			envMetadataProvider{envKey: envAWSInstanceID},
			ec2MetadataProvider{client: client, metadataKey: metadataInstanceID},
		)),
		WithResourceARN(getMetadata(
			simpleMetadataProvider{metadata: cfg.ResourceARN},
			simpleMetadataProvider{metadata: settings.ResourceARN},
		)),
	}
}

// NewSender creates a new Sender with a default interval and queue size.
func NewSender(client awsxray.XRayClient, opts ...Option) Sender {
	return newSender(client, opts...)
}

func newSender(client awsxray.XRayClient, opts ...Option) *telemetrySender {
	sender := &telemetrySender{
		client:    client,
		interval:  defaultInterval,
		queueSize: defaultQueueSize,
		batchSize: defaultBatchSize,
		stopCh:    make(chan struct{}),
		Recorder:  NewRecorder(),
	}
	for _, opt := range opts {
		opt.apply(sender)
	}
	return sender
}

// Start starts the loop to send the records.
func (ts *telemetrySender) Start() {
	ts.startOnce.Do(func() {
		ts.stopWait.Add(1)
		go func() {
			defer ts.stopWait.Done()
			ts.run()
		}()
	})
}

// Stop closes the stopCh channel to stop the loop.
func (ts *telemetrySender) Stop() {
	ts.stopOnce.Do(func() {
		close(ts.stopCh)
		ts.stopWait.Wait()
	})
}

// run sends the queued records once a minute if telemetry data was updated.
func (ts *telemetrySender) run() {
	ticker := time.NewTicker(ts.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ts.stopCh:
			return
		case <-ticker.C:
			if ts.HasRecording() {
				// xray.TelemetryRecord를 types.TelemetryRecord로 변환하여 enqueue
				v1Record := ts.Rotate()
				if v1Record != nil {
					v2Record := convertV1RecordToV2(v1Record)
					ts.enqueue(v2Record)
				}
				ts.send()
			}
		}
	}
}

// enqueue the record. If queue is full, drop the head of the queue and add.
func (ts *telemetrySender) enqueue(record types.TelemetryRecord) {
	for len(ts.queue) >= ts.queueSize {
		var dropped types.TelemetryRecord
		dropped, ts.queue = ts.queue[0], ts.queue[1:]
		if ts.logger != nil {
			ts.logger.Debug("queue full, dropping telemetry record", 
				zap.Time("dropped_timestamp", *dropped.Timestamp))
		}
	}
	ts.queue = append(ts.queue, record)
}

// v1 TelemetryRecord를 v2 types.TelemetryRecord로 변환하는 함수
func convertV1RecordToV2(record *types.TelemetryRecord) types.TelemetryRecord {
	v2Record := types.TelemetryRecord{
		SegmentsReceivedCount:  record.SegmentsReceivedCount,
		SegmentsRejectedCount:  record.SegmentsRejectedCount,
		SegmentsSentCount:      record.SegmentsSentCount,
		SegmentsSpilloverCount: record.SegmentsSpilloverCount,
		Timestamp:              record.Timestamp,
	}

	if record.BackendConnectionErrors != nil {
		v2Record.BackendConnectionErrors = &types.BackendConnectionErrors{
			HTTPCode4XXCount:       record.BackendConnectionErrors.HTTPCode4XXCount,
			HTTPCode5XXCount:       record.BackendConnectionErrors.HTTPCode5XXCount,
			ConnectionRefusedCount: record.BackendConnectionErrors.ConnectionRefusedCount,
			OtherCount:             record.BackendConnectionErrors.OtherCount,
			TimeoutCount:           record.BackendConnectionErrors.TimeoutCount,
			UnknownHostCount:       record.BackendConnectionErrors.UnknownHostCount,
		}
	}

	return v2Record
}

// send the records in the queue in batches. Updates the queue.
func (ts *telemetrySender) send() {
	ctx := context.Background()
	
	for i := len(ts.queue); i >= 0; i -= ts.batchSize {
		startIndex := i - ts.batchSize
		if startIndex < 0 {
			startIndex = 0
		}
		
		if startIndex >= i {
			continue
		}

		input := &xray.PutTelemetryRecordsInput{
			EC2InstanceId:    &ts.instanceID,
			Hostname:         &ts.hostname,
			ResourceARN:      &ts.resourceARN,
			TelemetryRecords: ts.queue[startIndex:i],
		}
		
		if _, err := ts.client.PutTelemetryRecords(ctx, input); err != nil {
			ts.RecordConnectionError(err)
			ts.queue = ts.queue[:i]
			return
		}
	}
	ts.queue = ts.queue[:0]
}