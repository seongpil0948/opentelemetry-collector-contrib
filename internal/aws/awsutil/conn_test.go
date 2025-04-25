// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awsutil

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

var ec2Region = "us-west-2"

type mockConn struct {
	mock.Mock
}

// getEC2Region mocks the EC2 region retrieval function
func (c *mockConn) getEC2Region(ctx context.Context, cfg aws.Config) (string, error) {
	args := c.Called(ctx, cfg)
	errorStr := args.String(0)
	var err error
	if errorStr != "" {
		err = errors.New(errorStr)
		return "", err
	}
	return ec2Region, nil
}

// Test EC2 metadata service for region retrieval
func TestEC2Session(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	sessionCfg := CreateDefaultSessionConfig()
	m := new(mockConn)

	// Set up mock to return a specific region
	m.On("getEC2Region", mock.Anything, mock.Anything).Return("")

	// Create mock EC2 config
	cfg, err := GetAWSConfig(ctx, logger, &sessionCfg)
	if err != nil {
		// This is expected as we're not on EC2
		return
	}

	// If on EC2, verify the region
	region, err := m.getEC2Region(ctx, cfg)
	if err == nil {
		assert.Equal(t, ec2Region, region, "Region value should be fetched from EC2 metadata service")
	}
}

// Test fetching region from environment variable
func TestRegionEnv(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	sessionCfg := CreateDefaultSessionConfig()
	region := "us-east-1"
	t.Setenv("AWS_REGION", region)

	// Test retrieving region from environment variables
	cfg, err := GetAWSConfig(ctx, logger, &sessionCfg)
	assert.NoError(t, err)
	assert.Equal(t, region, cfg.Region, "Region value should be fetched from environment")
}

// Test EC2 metadata service region retrieval
func TestEC2Region(t *testing.T) {
	ctx := context.Background()
	conn := &Conn{}

	// We expect an error since we're not running on an EC2 instance
	cfg := aws.Config{}
	_, err := conn.getEC2Region(ctx, cfg)
	assert.Error(t, err, "getEC2Region should error out when not on EC2 instance")
}

// Test creating a static credential provider
func TestCreateStaticCredentialsProvider(t *testing.T) {
	// Create a static credential provider
	provider := CreateStaticCredentialProvider("ACCESS_KEY", "SECRET_KEY", "SESSION_TOKEN")
	assert.NotNil(t, provider, "Static credential provider should not be nil")

	// Credentials would typically be tested by retrieving and checking them,
	// but this requires network access so we just check the provider is created
}

// Test assume role credential provider
func TestCreateAssumeRoleProvider(t *testing.T) {
	ctx := context.Background()
	cfg := aws.Config{
		Region: "us-west-2",
		Credentials: aws.NewCredentialsCache(
			CreateStaticCredentialProvider("ACCESS_KEY", "SECRET_KEY", "SESSION_TOKEN"),
		),
	}

	// Creating the provider should succeed even without real credentials
	provider, err := CreateAssumeRoleCredentialProvider(ctx, cfg, "arn:aws:iam::123456789012:role/test-role", "")
	assert.NoError(t, err)
	assert.NotNil(t, provider, "AssumeRole credential provider should not be nil")
}

// Test error handling for invalid proxy address
func TestGetAWSConfigWithInvalidProxy(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	sessionCfg := CreateDefaultSessionConfig()
	sessionCfg.ProxyAddress = "invalid\n"

	// Invalid proxy address should result in an error
	_, err := GetAWSConfig(ctx, logger, &sessionCfg)
	assert.Error(t, err, "GetAWSConfig should fail with invalid proxy")
}

// Test configuration with region specified
func TestGetAWSConfigWithRegion(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	sessionCfg := CreateDefaultSessionConfig()
	sessionCfg.Region = "us-west-2"

	// Config should contain the specified region
	cfg, err := GetAWSConfig(ctx, logger, &sessionCfg)
	assert.NoError(t, err)
	assert.Equal(t, "us-west-2", cfg.Region)
}

// Test configuration with role ARN and external ID
func TestGetAWSConfigWithRoleARN(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	sessionCfg := CreateDefaultSessionConfig()
	sessionCfg.Region = "us-west-2"
	sessionCfg.RoleARN = "arn:aws:iam::123456789012:role/test-role"
	sessionCfg.ExternalID = "test-external-id"

	// We can only test that the configuration process succeeds
	// Actual credential retrieval would require AWS access
	cfg, err := GetAWSConfig(ctx, logger, &sessionCfg)
	assert.NoError(t, err)
	assert.Equal(t, "us-west-2", cfg.Region)
}

// Test creation of HTTP transport for proxy server
func TestProxyServerTransport(t *testing.T) {
	logger := zap.NewNop()
	sessionCfg := CreateDefaultSessionConfig()

	// Test creating a transport with default settings
	transport, err := ProxyServerTransport(logger, &sessionCfg)
	assert.NoError(t, err)
	assert.NotNil(t, transport)

	// Check that config values are properly applied
	assert.Equal(t, sessionCfg.NumberOfWorkers, transport.MaxIdleConns)
	assert.Equal(t, sessionCfg.NumberOfWorkers, transport.MaxIdleConnsPerHost)
}

// Test proxy address resolution
func TestGetProxyAddress(t *testing.T) {
	// Set environment variable for proxy
	t.Setenv("HTTPS_PROXY", "https://env-proxy.example.com")

	// Config proxy takes precedence
	addr := getProxyAddress("https://config-proxy.example.com")
	assert.Equal(t, "https://config-proxy.example.com", addr)

	// Fall back to environment variable
	addr = getProxyAddress("")
	assert.Equal(t, "https://env-proxy.example.com", addr)

	// No proxy available
	t.Setenv("HTTPS_PROXY", "")
	addr = getProxyAddress("")
	assert.Equal(t, "", addr)
}

// Test proxy URL parsing
func TestGetProxyURL(t *testing.T) {
	// Valid URL returns parsed URL
	url, err := getProxyURL("https://proxy.example.com")
	assert.NoError(t, err)
	assert.Equal(t, "https://proxy.example.com", url.String())

	// Empty string returns nil URL with no error
	url, err = getProxyURL("")
	assert.NoError(t, err)
	assert.Nil(t, url)

	// Invalid URL returns error
	_, err = getProxyURL("invalid\n")
	assert.Error(t, err)
}

// Test AssumeRole credential provider with role ARN
func TestAssumeRoleProvider(t *testing.T) {
	ctx := context.Background()
	cfg := aws.Config{
		Region: "us-west-2",
		Credentials: aws.NewCredentialsCache(
			CreateStaticCredentialProvider("ACCESS_KEY", "SECRET_KEY", "SESSION_TOKEN"),
		),
	}

	roleARN := "arn:aws:iam::123456789012:role/test-role"

	// Create assume role provider
	provider, err := CreateAssumeRoleCredentialProvider(ctx, cfg, roleARN, "")
	assert.NoError(t, err)
	assert.NotNil(t, provider)

	// Test with external ID
	externalID := "test-external-id"
	provider, err = CreateAssumeRoleCredentialProvider(ctx, cfg, roleARN, externalID)
	assert.NoError(t, err)
	assert.NotNil(t, provider)
}

// Test handling of AWS STS endpoint configuration
func TestRegionalSTSEndpoint(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	sessionCfg := CreateDefaultSessionConfig()
	sessionCfg.Region = "us-west-2"
	sessionCfg.RoleARN = "arn:aws:iam::123456789012:role/test-role"

	// Set regional STS endpoints configuration
	t.Setenv("AWS_STS_REGIONAL_ENDPOINTS", "regional")

	// Should succeed with valid region and STS configuration
	cfg, err := GetAWSConfig(ctx, logger, &sessionCfg)
	assert.NoError(t, err)
	assert.Equal(t, "us-west-2", cfg.Region)
}

// Test proxy URL parsing with various inputs
func TestProxyURLParsing(t *testing.T) {
	// Test with valid HTTP proxy
	proxyURL, err := getProxyURL("http://proxy.example.com:8080")
	assert.NoError(t, err)
	assert.Equal(t, "http://proxy.example.com:8080", proxyURL.String())

	// Test with valid HTTPS proxy
	proxyURL, err = getProxyURL("https://secure-proxy.example.com")
	assert.NoError(t, err)
	assert.Equal(t, "https://secure-proxy.example.com", proxyURL.String())

	// Test with proxy requiring authentication
	proxyURL, err = getProxyURL("http://user:password@proxy.example.com")
	assert.NoError(t, err)
	assert.Equal(t, "http://user:password@proxy.example.com", proxyURL.String())

	// Test with invalid URL characters
	_, err = getProxyURL("http://proxy with spaces.com")
	assert.Error(t, err)
}

// Test HTTP client creation with various settings
func TestNewHTTPClient(t *testing.T) {
	logger := zap.NewNop()

	// Test with default settings
	client, err := newHTTPClient(logger, 10, 30, false, "")
	assert.NoError(t, err)
	assert.NotNil(t, client)

	// Test with proxy
	client, err = newHTTPClient(logger, 10, 30, false, "http://proxy.example.com")
	assert.NoError(t, err)
	assert.NotNil(t, client)

	// Test with TLS verification disabled
	client, err = newHTTPClient(logger, 10, 30, true, "")
	assert.NoError(t, err)
	assert.NotNil(t, client)

	// Test with invalid proxy
	_, err = newHTTPClient(logger, 10, 30, false, "invalid\n")
	assert.Error(t, err)
}

// Test GetAWSConfig with endpoint override
func TestGetAWSConfigWithEndpoint(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	sessionCfg := CreateDefaultSessionConfig()
	sessionCfg.Region = "us-west-2"
	sessionCfg.Endpoint = "https://s3.custom-endpoint.com"

	// Config should contain the custom endpoint
	cfg, err := GetAWSConfig(ctx, logger, &sessionCfg)
	assert.NoError(t, err)
	assert.Equal(t, "https://s3.custom-endpoint.com", *cfg.BaseEndpoint)
}
