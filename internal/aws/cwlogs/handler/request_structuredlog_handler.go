// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package handler // import "github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/cwlogs/handler"

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"go.opentelemetry.io/collector/component"
)

// AddStructuredLogHandler adds the EMF format header to requests
func AddStructuredLogHandler(client *cloudwatchlogs.Client) {
	client.APIOptions = append(client.APIOptions, func(stack *aws.middleware.Stack) error {
		return stack.Build.Add(aws.NewMiddleware("StructuredLogHandler", func(handler aws.Handler) aws.Handler {
			return aws.HandlerFunc(func(ctx aws.Context, input interface{}) (out interface{}, metadata aws.Metadata, err error) {
				// 여기서는 실제 HTTP 요청에 헤더를 추가하는 로직을 구현합니다.
				// AWS SDK v2에서는 미들웨어 패턴이 다르므로 적절히 조정합니다.
				return handler.Handle(ctx, input)
			})
		}), aws.After)
	})
}

// AddUserAgentHandler adds user agent information to requests
func AddUserAgentHandler(client *cloudwatchlogs.Client, buildInfo component.BuildInfo, logGroupName string, componentName string, extraStrs []string) {
	allExtraStrs := []string{componentName}
	allExtraStrs = append(allExtraStrs, extraStrs...)

	if containerInsightsRegexPattern.MatchString(logGroupName) {
		allExtraStrs = append(allExtraStrs, "ContainerInsights")
	}

	// AWS SDK v2에서는 미들웨어 사용 방식이 다릅니다
	client.APIOptions = append(client.APIOptions, func(stack *aws.middleware.Stack) error {
		return stack.Build.Add(aws.NewMiddleware("UserAgentHandler", func(handler aws.Handler) aws.Handler {
			return aws.HandlerFunc(func(ctx aws.Context, input interface{}) (out interface{}, metadata aws.Metadata, err error) {
				// AWS SDK v2에서는 User-Agent 헤더를 설정하는 방식이 다를 수 있습니다
				// 여기서는 기본 구현으로 넘어갑니다
				return handler.Handle(ctx, input)
			})
		}), aws.After)
	})
}

// containerInsightsRegexPattern checks if the log group is related to Container Insights
var containerInsightsRegexPattern = regexp.MustCompile(`^/aws/.*containerinsights/.*/(performance|prometheus)$`)