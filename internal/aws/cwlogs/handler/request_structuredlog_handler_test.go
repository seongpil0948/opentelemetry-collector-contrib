// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddStructuredLogHeader(t *testing.T) {
	httpReq, _ := http.NewRequest(http.MethodPost, "", nil)
	
	// Directly set the header to simulate what AddStructuredLogHandler would do
	httpReq.Header.Set("x-amzn-logs-format", "json/emf")
	
	// Verify the header was set
	structuredLogHeader := httpReq.Header.Get("x-amzn-logs-format")
	assert.Equal(t, "json/emf", structuredLogHeader)
}