// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package skywalkingencodingextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/encoding/skywalkingencodingextension"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

type skywalkingExtension struct {
	unmarshaler ptrace.Unmarshaler
}

func (e *skywalkingExtension) UnmarshalTraces(buf []byte) (ptrace.Traces, error) {
	return e.unmarshaler.UnmarshalTraces(buf)
}

func (*skywalkingExtension) Start(context.Context, component.Host) error {
	return nil
}

func (*skywalkingExtension) Shutdown(context.Context) error {
	return nil
}
