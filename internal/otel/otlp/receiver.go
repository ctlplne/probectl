// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otlp

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"

	// ARCH-006: register the gRPC gzip decompressor so the OTLP/gRPC receiver
	// can decode gzip-compressed messages (the OTel Collector's otlp exporter
	// gzips by default). Without this blank import the server returns
	// Unimplemented for "gzip" and every default-config push fails.
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/otel"
)

const defaultMaxRecvBytes = 4 << 20 // 4 MiB

// Sink consumes ingested OTLP metrics — already authenticated and tenant-scoped.
type Sink interface {
	ConsumeMetrics(ctx context.Context, tenant string, req *colmetricspb.ExportMetricsServiceRequest) error
}

// SinkFunc adapts a function to a Sink.
type SinkFunc func(ctx context.Context, tenant string, req *colmetricspb.ExportMetricsServiceRequest) error

// ConsumeMetrics implements Sink.
func (f SinkFunc) ConsumeMetrics(ctx context.Context, tenant string, req *colmetricspb.ExportMetricsServiceRequest) error {
	return f(ctx, tenant, req)
}

// NewBusSink returns a Sink that marshals each (already tenant-scoped) request
// and hands it to publish — e.g. a tenant-keyed bus topic. It keeps the OTLP
// package decoupled from internal/bus.
func NewBusSink(publish func(ctx context.Context, tenant string, payload []byte) error) Sink {
	return SinkFunc(func(ctx context.Context, tenant string, req *colmetricspb.ExportMetricsServiceRequest) error {
		payload, err := proto.Marshal(req)
		if err != nil {
			return fmt.Errorf("otlp: marshal ingested metrics: %w", err)
		}
		return publish(ctx, tenant, payload)
	})
}

// NewGRPCServer builds a TLS-only OTLP/gRPC receiver: the MetricsService with an
// authenticating, tenant-scoping interceptor and a bounded receive size. It
// fails closed if no TLS config is supplied — the receiver is never plaintext
// (CLAUDE.md §7 guardrail 12).
func NewGRPCServer(tlsCfg *tls.Config, auth Authenticator, sinks Sinks, maxRecvBytes int) (*grpc.Server, error) {
	if tlsCfg == nil {
		return nil, errors.New("otlp: TLS config required (the OTLP receiver is TLS-only)")
	}
	if auth == nil {
		return nil, errors.New("otlp: authenticator is required")
	}
	if err := sinks.validate(); err != nil {
		return nil, err
	}
	if maxRecvBytes <= 0 {
		maxRecvBytes = defaultMaxRecvBytes
	}
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.UnaryInterceptor(authUnaryInterceptor(auth)),
		grpc.MaxRecvMsgSize(maxRecvBytes),
	)
	// ARCH-001: all three OTLP signals, one contract.
	colmetricspb.RegisterMetricsServiceServer(srv, newMetricsService(sinks.Metrics))
	coltracepb.RegisterTraceServiceServer(srv, &traceService{sink: sinks.Traces})
	collogspb.RegisterLogsServiceServer(srv, &logsService{sink: sinks.Logs})
	return srv, nil
}

type metricsService struct {
	colmetricspb.UnimplementedMetricsServiceServer
	sink Sink
}

func newMetricsService(sink Sink) *metricsService { return &metricsService{sink: sink} }

// Export ingests an OTLP metrics push for the interceptor-resolved tenant.
func (s *metricsService) Export(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) (*colmetricspb.ExportMetricsServiceResponse, error) {
	tenant, ok := tenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "otlp: no authenticated tenant")
	}
	if err := scopeToTenant(req, tenant); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	if err := s.sink.ConsumeMetrics(ctx, tenant, req); err != nil {
		return nil, status.Error(codes.Internal, "otlp: sink error")
	}
	return &colmetricspb.ExportMetricsServiceResponse{}, nil
}

// MetricsHTTPHandler is the OTLP/HTTP metrics receiver: POST an
// ExportMetricsServiceRequest (protobuf), authenticated + tenant-scoped, with a
// bounded body (untrusted input). The caller must serve it over TLS.
func MetricsHTTPHandler(auth Authenticator, sink Sink, maxBytes int64) http.Handler {
	if maxBytes <= 0 {
		maxBytes = defaultMaxRecvBytes
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tenant, err := auth.Authenticate(r.Context(), bearerFromHeader(r.Header.Get("Authorization")))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := readOTLPBody(w, r, maxBytes)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var req colmetricspb.ExportMetricsServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid OTLP payload", http.StatusBadRequest)
			return
		}
		if err := scopeToTenant(&req, tenant); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if err := sink.ConsumeMetrics(r.Context(), tenant, &req); err != nil {
			http.Error(w, "sink error", http.StatusInternalServerError)
			return
		}
		resp, _ := proto.Marshal(&colmetricspb.ExportMetricsServiceResponse{})
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(resp)
	})
}

// readOTLPBody reads the request body with a hard size bound and transparently
// decompresses gzip (ARCH-005): the OTel Collector's otlphttp exporter gzips by
// default, so a receiver that ignores Content-Encoding silently rejected every
// stock-config push as an "invalid OTLP payload". The MaxBytesReader bound is
// applied to the COMPRESSED stream and the decompressed output is bounded again
// to maxBytes, so a gzip bomb can't blow past the limit (untrusted input).
func readOTLPBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	limited := http.MaxBytesReader(w, r.Body, maxBytes)
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(limited)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		return io.ReadAll(io.LimitReader(gz, maxBytes))
	}
	return io.ReadAll(limited)
}

// scopeToTenant enforces tenant isolation on ingested OTLP: a ResourceMetrics
// that names a DIFFERENT tenant is rejected; one with no tenant is stamped with
// the authenticated tenant. It mutates req in place.
func scopeToTenant(req *colmetricspb.ExportMetricsServiceRequest, tenant string) error {
	for _, rm := range req.GetResourceMetrics() {
		if rt := ResourceTenant(rm); rt != "" && rt != tenant {
			return fmt.Errorf("otlp: resource tenant %q does not match authenticated tenant", rt)
		}
		stampTenant(rm, tenant)
	}
	return nil
}

func stampTenant(rm *metricspb.ResourceMetrics, tenant string) {
	if ResourceTenant(rm) != "" {
		return
	}
	if rm.Resource == nil {
		rm.Resource = &resourcepb.Resource{}
	}
	// Overwrite an existing EMPTY-valued tenant attribute in place: appending
	// after it would let the empty value shadow the stamp for first-match
	// readers (ResourceTenant) — fuzz-found via FuzzOTLPPayload (U-082).
	for _, kv := range rm.Resource.Attributes {
		if kv.GetKey() == otel.AttrTenantID {
			kv.Value = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: tenant}}
			return
		}
	}
	rm.Resource.Attributes = append(rm.Resource.Attributes, &commonpb.KeyValue{
		Key:   otel.AttrTenantID,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: tenant}},
	})
}
