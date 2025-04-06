// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awsxrayexporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/awsxrayexporter"

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/xray"
	"github.com/aws/smithy-go"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/awsxrayexporter/internal/translator"
	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/awsutil"
	awsxray "github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/xray"
	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/xray/telemetry"
)

const (
	maxSegmentsPerPut = int(50) // limit imposed by PutTraceSegments API
)

// newTracesExporter creates an exporter.Traces that converts to an X-Ray PutTraceSegments
// request and then posts the request to the configured region's X-Ray endpoint.
func newTracesExporter(
	cfg *Config,
	set exporter.Settings,
	cn awsutil.ConnAttr,
	registry telemetry.Registry,
) (exporter.Traces, error) {
	typeLog := zap.String("type", set.ID.Type().String())
	nameLog := zap.String("name", set.ID.String())
	logger := set.Logger

	ctx := context.Background()
	awsCfg, err := awsxray.LoadDefaultAWSConfig(ctx, cfg.Region)
	if err != nil {
		return nil, err
	}
	xrayClient := awsxray.NewXRayClient(ctx, logger, awsCfg, set.BuildInfo)
	
	sender := telemetry.NewNopSender()
	if cfg.TelemetryConfig.Enabled {
		// 원래 옵션 변환 로직이 있다면 여기에 추가
		// opts := telemetry.ToOptions(cfg.TelemetryConfig, session, &cfg.AWSSessionSettings)
		opts := []telemetry.Option{telemetry.WithLogger(set.Logger)}
		sender = registry.Register(set.ID, cfg.TelemetryConfig, xrayClient, opts...)
	}
	
	return exporterhelper.NewTraces(
		ctx,
		set,
		cfg,
		func(ctx context.Context, td ptrace.Traces) error {
			var err error
			logger.Debug("TracesExporter", typeLog, nameLog, zap.Int("#spans", td.SpanCount()))

			documents := extractResourceSpans(cfg, logger, td)

			for offset := 0; offset < len(documents); offset += maxSegmentsPerPut {
				var nextOffset int
				if offset+maxSegmentsPerPut > len(documents) {
					nextOffset = len(documents)
				} else {
					nextOffset = offset + maxSegmentsPerPut
				}
				
				input := &xray.PutTraceSegmentsInput{
					TraceSegmentDocuments: documents[offset:nextOffset],
				}
				
				logger.Debug("sending X-Ray segments", 
					zap.Int("segment_count", len(input.TraceSegmentDocuments)))
				
				output, localErr := xrayClient.PutTraceSegments(ctx, input)
				if localErr != nil {
					logger.Debug("response error", zap.Error(localErr))
					err = wrapErrorIfBadRequest(localErr) // record error
					sender.RecordConnectionError(localErr)
				} else {
					sender.RecordSegmentsSent(len(input.TraceSegmentDocuments))
				}
				
				if output != nil {
					logger.Debug("received X-Ray response", 
						zap.Int("unprocessed_count", len(output.UnprocessedTraceSegments)))
				}
				
				if err != nil {
					break
				}
			}
			return err
		},
		exporterhelper.WithStart(func(ctx context.Context, host component.Host) error {
			sender.Start()
			return nil
		}),
		exporterhelper.WithShutdown(func(ctx context.Context) error {
			sender.Stop()
			_ = logger.Sync()
			return nil
		}),
	)
}

func extractResourceSpans(config component.Config, logger *zap.Logger, td ptrace.Traces) []string {
	documents := make([]string, 0, td.SpanCount())

	for i := 0; i < td.ResourceSpans().Len(); i++ {
		rspans := td.ResourceSpans().At(i)
		resource := rspans.Resource()
		for j := 0; j < rspans.ScopeSpans().Len(); j++ {
			spans := rspans.ScopeSpans().At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				documentsForSpan, localErr := translator.MakeSegmentDocuments(
					spans.At(k), resource,
					config.(*Config).IndexedAttributes,
					config.(*Config).IndexAllAttributes,
					config.(*Config).LogGroupNames,
					config.(*Config).skipTimestampValidation)

				if localErr != nil {
					logger.Debug("Error translating span.", zap.Error(localErr))
					continue
				}

				documents = append(documents, documentsForSpan...)
			}
		}
	}
	return documents
}

func wrapErrorIfBadRequest(err error) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		// 4xx Error or 5xx Error
		if code := apiErr.ErrorCode(); code == "InvalidRequestException" || 
		   code == "ThrottledException" || 
		   strings.HasPrefix(code, "Client") || 
		   strings.HasPrefix(code, "Validation") {
			return consumererror.NewPermanent(err)
		}
	}
	return err
}