package otlp

import (
	"context"
	"crypto/tls"
	"testing"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

func TestNewServerValidates(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"tok": "tenant-a"})
	sink := testSinks(SinkFunc(func(context.Context, string, *colmetricspb.ExportMetricsServiceRequest) error { return nil }))
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if _, err := NewServer(ServerConfig{GRPCAddr: ":0"}, nil, auth, sink, nil); err == nil {
		t.Error("nil TLS config should fail (TLS-only)")
	}
	if _, err := NewServer(ServerConfig{}, tlsCfg, auth, sink, nil); err == nil {
		t.Error("no listen address should fail")
	}
	if _, err := NewServer(ServerConfig{GRPCAddr: ":0"}, tlsCfg, nil, sink, nil); err == nil {
		t.Error("nil authenticator should fail")
	}
	if _, err := NewServer(ServerConfig{HTTPAddr: ":0"}, tlsCfg, auth, sink, nil); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

// testSinks wraps a metrics sink with no-op trace/log sinks (the metrics
// mechanics tests predate the three-signal receiver).
func testSinks(m Sink) Sinks {
	return Sinks{
		Metrics: m,
		Traces: TraceSinkFunc(func(context.Context, string, *coltracepb.ExportTraceServiceRequest) error {
			return nil
		}),
		Logs: LogSinkFunc(func(context.Context, string, *collogspb.ExportLogsServiceRequest) error {
			return nil
		}),
	}
}
