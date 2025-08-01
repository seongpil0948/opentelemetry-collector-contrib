// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package skywalkingreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/skywalkingreceiver"

// This file implements factory for skywalking receiver.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/confignet"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/sharedcomponent"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/skywalkingreceiver/internal/metadata"
)

const (
	// Protocol values.
	protoGRPC = "grpc"
	protoHTTP = "http"

	// Default endpoints to bind to.
	defaultGRPCEndpoint = "localhost:11800"
	defaultHTTPEndpoint = "localhost:12800"
)

// NewFactory creates a new Skywalking receiver factory.
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		receiver.WithTraces(createTracesReceiver, metadata.TracesStability),
		receiver.WithMetrics(createMetricsReceiver, metadata.MetricsStability))
}

// CreateDefaultConfig creates the default configuration for Skywalking receiver.
func createDefaultConfig() component.Config {
	return &Config{
		Protocols: Protocols{
			GRPC: &configgrpc.ServerConfig{
				NetAddr: confignet.AddrConfig{
					Endpoint:  defaultGRPCEndpoint,
					Transport: confignet.TransportTypeTCP,
				},
			},
			HTTP: &confighttp.ServerConfig{
				Endpoint: defaultHTTPEndpoint,
			},
		},
	}
}

// createTracesReceiver creates a trace receiver based on provided config.
func createTracesReceiver(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	nextConsumer consumer.Traces,
) (receiver.Traces, error) {
	// Convert settings in the source c to configuration struct
	// that Skywalking receiver understands.
	rCfg := cfg.(*Config)

	c, err := createConfiguration(rCfg)
	if err != nil {
		return nil, err
	}

	r := receivers.GetOrAdd(cfg, func() component.Component {
		return newSkywalkingReceiver(c, set)
	})

	err = r.Unwrap().(*swReceiver).registerTraceConsumer(nextConsumer)
	if err != nil {
		return nil, err
	}

	return r, nil
}

// createMetricsReceiver creates a metrics receiver based on provided config.
func createMetricsReceiver(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	nextConsumer consumer.Metrics,
) (receiver.Metrics, error) {
	// Convert settings in the source c to configuration struct
	// that Skywalking receiver understands.
	rCfg := cfg.(*Config)

	c, err := createConfiguration(rCfg)
	if err != nil {
		return nil, err
	}

	r := receivers.GetOrAdd(cfg, func() component.Component {
		return newSkywalkingReceiver(c, set)
	})

	err = r.Unwrap().(*swReceiver).registerMetricsConsumer(nextConsumer)
	if err != nil {
		return nil, err
	}

	return r, nil
}

// create the config that Skywalking receiver will use.
func createConfiguration(rCfg *Config) (*configuration, error) {
	var err error
	var c configuration
	// Set ports
	if rCfg.GRPC != nil {
		c.CollectorGRPCServerSettings = *rCfg.GRPC
		if c.CollectorGRPCPort, err = extractPortFromEndpoint(rCfg.GRPC.NetAddr.Endpoint); err != nil {
			return nil, fmt.Errorf("unable to extract port for the gRPC endpoint: %w", err)
		}
	}

	if rCfg.HTTP != nil {
		c.CollectorHTTPSettings = *rCfg.HTTP
		if c.CollectorHTTPPort, err = extractPortFromEndpoint(rCfg.HTTP.Endpoint); err != nil {
			return nil, fmt.Errorf("unable to extract port for the HTTP endpoint: %w", err)
		}
	}
	return &c, nil
}

// extract the port number from string in "address:port" format. If the
// port number cannot be extracted returns an error.
func extractPortFromEndpoint(endpoint string) (int, error) {
	_, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return 0, fmt.Errorf("endpoint is not formatted correctly: %w", err)
	}
	port, err := strconv.ParseInt(portStr, 10, 0)
	if err != nil {
		return 0, fmt.Errorf("endpoint port is not a number: %w", err)
	}
	if port < 1 || port > 65535 {
		return 0, errors.New("port number must be between 1 and 65535")
	}
	return int(port), nil
}

var receivers = sharedcomponent.NewSharedComponents()
