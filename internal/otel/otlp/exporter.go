// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otlp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// ExporterConfig configures an OTLP exporter (to an external collector).
type ExporterConfig struct {
	Endpoint string      // host:port (gRPC) or full URL (HTTP)
	Token    string      // bearer token, sent as "Authorization: Bearer <token>"
	TLS      *tls.Config // TLS for the connection (required unless Insecure)
	Insecure bool        // dev/test only: plaintext transport (never in production)
}

// GRPCExporter exports OTLP metrics, traces, and logs over OTLP/gRPC
// (ARCH-003: traces+logs are first-class export, no longer ingest-only).
type GRPCExporter struct {
	conn   *grpc.ClientConn
	client colmetricspb.MetricsServiceClient
	traces coltracepb.TraceServiceClient
	logs   collogspb.LogsServiceClient
	token  string
}

// NewGRPCExporter dials the collector. Extra dial options (e.g. a test dialer)
// are appended. TLS is required unless cfg.Insecure is set.
func NewGRPCExporter(cfg ExporterConfig, dialOpts ...grpc.DialOption) (*GRPCExporter, error) {
	var creds grpc.DialOption
	switch {
	case cfg.Insecure:
		creds = grpc.WithTransportCredentials(insecure.NewCredentials())
	case cfg.TLS != nil:
		creds = grpc.WithTransportCredentials(credentials.NewTLS(cfg.TLS))
	default:
		return nil, errors.New("otlp: gRPC exporter requires a TLS config (or Insecure for dev)")
	}
	conn, err := grpc.NewClient(cfg.Endpoint, append([]grpc.DialOption{creds}, dialOpts...)...)
	if err != nil {
		return nil, fmt.Errorf("otlp: dial %q: %w", cfg.Endpoint, err)
	}
	return &GRPCExporter{
		conn:   conn,
		client: colmetricspb.NewMetricsServiceClient(conn),
		traces: coltracepb.NewTraceServiceClient(conn),
		logs:   collogspb.NewLogsServiceClient(conn),
		token:  cfg.Token,
	}, nil
}

func (e *GRPCExporter) authCtx(ctx context.Context) context.Context {
	if e.token != "" {
		return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+e.token)
	}
	return ctx
}

// ExportMetrics sends an OTLP metrics request, attaching the bearer token.
func (e *GRPCExporter) ExportMetrics(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) error {
	_, err := e.client.Export(e.authCtx(ctx), req)
	return err
}

// ExportTraces sends an OTLP traces request (ARCH-003).
func (e *GRPCExporter) ExportTraces(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) error {
	_, err := e.traces.Export(e.authCtx(ctx), req)
	return err
}

// ExportLogs sends an OTLP logs request (ARCH-003).
func (e *GRPCExporter) ExportLogs(ctx context.Context, req *collogspb.ExportLogsServiceRequest) error {
	_, err := e.logs.Export(e.authCtx(ctx), req)
	return err
}

// Close releases the connection.
func (e *GRPCExporter) Close() error { return e.conn.Close() }

// HTTPExporter exports OTLP metrics, traces, and logs over OTLP/HTTP (protobuf).
type HTTPExporter struct {
	url    string
	token  string
	client *http.Client
}

// NewHTTPExporter builds an OTLP/HTTP exporter. Production endpoints are https;
// cfg.TLS customizes the client's TLS (e.g. a private CA).
func NewHTTPExporter(cfg ExporterConfig) (*HTTPExporter, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("otlp: HTTP exporter requires an endpoint URL")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.TLS != nil {
		tr.TLSClientConfig = cfg.TLS
	}
	return &HTTPExporter{url: cfg.Endpoint, token: cfg.Token, client: &http.Client{Transport: tr}}, nil
}

// ExportMetrics POSTs an OTLP metrics request as protobuf.
func (e *HTTPExporter) ExportMetrics(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) error {
	return e.post(ctx, e.signalURL("metrics"), req)
}

// ExportTraces POSTs an OTLP traces request as protobuf (ARCH-003).
func (e *HTTPExporter) ExportTraces(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) error {
	return e.post(ctx, e.signalURL("traces"), req)
}

// ExportLogs POSTs an OTLP logs request as protobuf (ARCH-003).
func (e *HTTPExporter) ExportLogs(ctx context.Context, req *collogspb.ExportLogsServiceRequest) error {
	return e.post(ctx, e.signalURL("logs"), req)
}

// signalURL derives the per-signal OTLP/HTTP path. The configured URL is the
// metrics endpoint (.../v1/metrics by convention); traces/logs are its
// /v1/{traces,logs} siblings. If the URL ends in a known signal segment we swap
// it; otherwise we append /v1/<signal> to the base.
func (e *HTTPExporter) signalURL(signal string) string {
	u := strings.TrimRight(e.url, "/")
	for _, s := range []string{"metrics", "traces", "logs"} {
		if strings.HasSuffix(u, "/v1/"+s) {
			return strings.TrimSuffix(u, "/v1/"+s) + "/v1/" + signal
		}
	}
	if strings.HasSuffix(u, "/"+signal) {
		return u
	}
	return u + "/v1/" + signal
}

func (e *HTTPExporter) post(ctx context.Context, url string, req proto.Message) error {
	body, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("otlp: marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	if e.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+e.token)
	}
	resp, err := e.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("otlp: export rejected: %s", resp.Status)
	}
	return nil
}
