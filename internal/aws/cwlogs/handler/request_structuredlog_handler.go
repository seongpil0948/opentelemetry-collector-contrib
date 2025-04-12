// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package handler // import "github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/cwlogs/handler"

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	// AWS SDK v2 core and CloudWatch Logs service client
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	// Smithy middleware types used by AWS SDK v2
	"github.com/aws/smithy-go/middleware"
	"github.com/aws/smithy-go/transport/http" // Required for accessing HTTP Request details like headers

	// OTel Collector component info
	"go.opentelemetry.io/collector/component"
)

// --- Structured Log Middleware ---

type structuredLogMiddleware struct{}

// ID returns the middleware identifier.
func (m *structuredLogMiddleware) ID() string { return "StructuredLogHandler" }

// HandleBuild implements the middleware.BuildMiddleware interface.
// This function is called during the build phase of the request lifecycle.
// NOTE: The original V1 code provided was effectively a no-op.
// If specific behavior like adding a header is needed, implement it here.
func (m *structuredLogMiddleware) HandleBuild(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (
	out middleware.BuildOutput, metadata middleware.Metadata, err error,
) {
	// Example: If you needed to add a specific header for structured logs:
	// if req, ok := in.Request.(*http.Request); ok {
	//    req.Header.Set("X-Amz-Client-Request-Type", "StructuredLog") // Example header
	// }

	// Pass control to the next middleware in the stack.
	return next.HandleBuild(ctx, in)
}

// AddStructuredLogHandler adds a custom middleware to the CloudWatch Logs client's request pipeline.
// In V2, middleware is typically added via APIOptions().Set*Options.
func AddStructuredLogHandler(client *cloudwatchlogs.Client) {
	// 라인 50: client.APIOptions() 메서드 호출 확인 (괄호 있음)
	client.APIOptions().SetBuildOptions(append(client.APIOptions().BuildOptions, &structuredLogMiddleware{}))
}

// --- User Agent Middleware ---

type userAgentMiddleware struct {
	buildInfo     component.BuildInfo
	logGroupName  string
	componentName string
	extraStrs     []string
}

// ID returns the middleware identifier.
func (m *userAgentMiddleware) ID() string { return "UserAgentHandler" }

// HandleBuild implements the middleware.BuildMiddleware interface.
// This function modifies the User-Agent header during the build phase.
func (m *userAgentMiddleware) HandleBuild(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (
	out middleware.BuildOutput, metadata middleware.Metadata, err error,
) {
	// We need access to the underlying HTTP request to modify headers.
	req, ok := in.Request.(*http.Request)
	if !ok {
		// If it's not an HTTP request, we can't set the User-Agent header.
		// Proceed without modification.
		return next.HandleBuild(ctx, in)
	}

	allExtraStrs := []string{m.componentName}
	if len(m.extraStrs) > 0 {
		allExtraStrs = append(allExtraStrs, m.extraStrs...)
	}

	if containerInsightsRegexPattern.MatchString(m.logGroupName) {
		allExtraStrs = append(allExtraStrs, "ContainerInsights")
	}

	// Construct the additional User-Agent string component.
	// Format: " componentName/version (extra1; extra2; ContainerInsights)"
	// Adjust the base component name and version source as needed.
	uaSuffix := fmt.Sprintf(" %s/%s (%s)",
		"otelcol-contrib", // Using a generic name, replace if needed
		m.buildInfo.Version, // Assumes BuildInfo has a Version field
		strings.Join(allExtraStrs, "; "),
	)

	// Append the suffix to the existing User-Agent header.
	currentUserAgent := req.Header.Get("User-Agent")
	req.Header.Set("User-Agent", currentUserAgent+uaSuffix)

	// Pass control to the next middleware in the stack.
	return next.HandleBuild(ctx, in)
}

// AddUserAgentHandler adds a custom middleware to append extra information to the User-Agent header.
func AddUserAgentHandler(client *cloudwatchlogs.Client, buildInfo component.BuildInfo, logGroupName string, componentName string, extraStrs []string) {
	middlewareToAdd := &userAgentMiddleware{
		buildInfo:     buildInfo,
		logGroupName:  logGroupName,
		componentName: componentName,
		extraStrs:     extraStrs,
	}

	// 라인 114: client.APIOptions() 메서드 호출 확인 (괄호 있음)
	client.APIOptions().SetBuildOptions(append(client.APIOptions().BuildOptions, middlewareToAdd))
}

// containerInsightsRegexPattern checks if the log group is related to Container Insights
// Ensure this pattern is correct for your use case.
var containerInsightsRegexPattern = regexp.MustCompile(`^/aws/.*containerinsights/.*/(performance|prometheus)$`)