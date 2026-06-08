package otlp

import (
	"context"
	"fmt"
	"io"
	"net/http"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/otel"
)

// OTLP traces + logs (ARCH-001): the receiver speaks all three OTLP signals,
// each with the SAME contract as metrics — TLS-only transport, authenticated
// push, tenant scoping enforced server-side (a resource naming a different
// tenant is rejected; an unstamped one is stamped), bounded untrusted input.

// TraceSink consumes ingested OTLP traces — authenticated and tenant-scoped.
type TraceSink interface {
	ConsumeTraces(ctx context.Context, tenant string, req *coltracepb.ExportTraceServiceRequest) error
}

// TraceSinkFunc adapts a function to a TraceSink.
type TraceSinkFunc func(ctx context.Context, tenant string, req *coltracepb.ExportTraceServiceRequest) error

// ConsumeTraces implements TraceSink.
func (f TraceSinkFunc) ConsumeTraces(ctx context.Context, tenant string, req *coltracepb.ExportTraceServiceRequest) error {
	return f(ctx, tenant, req)
}

// LogSink consumes ingested OTLP logs — authenticated and tenant-scoped.
type LogSink interface {
	ConsumeLogs(ctx context.Context, tenant string, req *collogspb.ExportLogsServiceRequest) error
}

// LogSinkFunc adapts a function to a LogSink.
type LogSinkFunc func(ctx context.Context, tenant string, req *collogspb.ExportLogsServiceRequest) error

// ConsumeLogs implements LogSink.
func (f LogSinkFunc) ConsumeLogs(ctx context.Context, tenant string, req *collogspb.ExportLogsServiceRequest) error {
	return f(ctx, tenant, req)
}

// Sinks bundles the three signal consumers. ALL are required: a receiver
// that silently dropped a signal would be the exact ARCH-001 failure shape.
type Sinks struct {
	Metrics Sink
	Traces  TraceSink
	Logs    LogSink
}

func (s Sinks) validate() error {
	if s.Metrics == nil || s.Traces == nil || s.Logs == nil {
		return fmt.Errorf("otlp: sinks for all three signals are required (metrics=%t traces=%t logs=%t)",
			s.Metrics != nil, s.Traces != nil, s.Logs != nil)
	}
	return nil
}

// NewBusTraceSink mirrors NewBusSink for the traces topic.
func NewBusTraceSink(publish func(ctx context.Context, tenant string, payload []byte) error) TraceSink {
	return TraceSinkFunc(func(ctx context.Context, tenant string, req *coltracepb.ExportTraceServiceRequest) error {
		payload, err := proto.Marshal(req)
		if err != nil {
			return fmt.Errorf("otlp: marshal ingested traces: %w", err)
		}
		return publish(ctx, tenant, payload)
	})
}

// NewBusLogSink mirrors NewBusSink for the logs topic.
func NewBusLogSink(publish func(ctx context.Context, tenant string, payload []byte) error) LogSink {
	return LogSinkFunc(func(ctx context.Context, tenant string, req *collogspb.ExportLogsServiceRequest) error {
		payload, err := proto.Marshal(req)
		if err != nil {
			return fmt.Errorf("otlp: marshal ingested logs: %w", err)
		}
		return publish(ctx, tenant, payload)
	})
}

// --- shared tenant scoping over the resource (all three signals) ---

// resourceTenantOf reads probectl.tenant.id from a resource.
func resourceTenantOf(res *resourcepb.Resource) string {
	for _, kv := range res.GetAttributes() {
		if kv.GetKey() == otel.AttrTenantID {
			return kv.GetValue().GetStringValue()
		}
	}
	return ""
}

// stampResource sets probectl.tenant.id on res (which must be non-nil),
// overwriting an empty-valued attribute in place (the U-082 fuzz finding:
// appending after an empty value lets it shadow the stamp).
func stampResource(res *resourcepb.Resource, tenant string) {
	for _, kv := range res.Attributes {
		if kv.GetKey() == otel.AttrTenantID {
			kv.Value = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: tenant}}
			return
		}
	}
	res.Attributes = append(res.Attributes, &commonpb.KeyValue{
		Key:   otel.AttrTenantID,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: tenant}},
	})
}

// scopeTracesToTenant enforces tenant isolation on ingested spans, exactly
// like scopeToTenant does for metrics.
func scopeTracesToTenant(req *coltracepb.ExportTraceServiceRequest, tenant string) error {
	for _, rs := range req.GetResourceSpans() {
		if rt := resourceTenantOf(rs.GetResource()); rt != "" && rt != tenant {
			return fmt.Errorf("otlp: resource tenant %q does not match authenticated tenant", rt)
		}
		if rs.Resource == nil {
			rs.Resource = &resourcepb.Resource{}
		}
		if resourceTenantOf(rs.Resource) == "" {
			stampResource(rs.Resource, tenant)
		}
	}
	return nil
}

// scopeLogsToTenant enforces tenant isolation on ingested log records.
func scopeLogsToTenant(req *collogspb.ExportLogsServiceRequest, tenant string) error {
	for _, rl := range req.GetResourceLogs() {
		if rt := resourceTenantOf(rl.GetResource()); rt != "" && rt != tenant {
			return fmt.Errorf("otlp: resource tenant %q does not match authenticated tenant", rt)
		}
		if rl.Resource == nil {
			rl.Resource = &resourcepb.Resource{}
		}
		if resourceTenantOf(rl.Resource) == "" {
			stampResource(rl.Resource, tenant)
		}
	}
	return nil
}

// --- gRPC services ---

type traceService struct {
	coltracepb.UnimplementedTraceServiceServer
	sink TraceSink
}

// Export ingests an OTLP traces push for the interceptor-resolved tenant.
func (s *traceService) Export(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	tenant, ok := tenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "otlp: no authenticated tenant")
	}
	if err := scopeTracesToTenant(req, tenant); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	if err := s.sink.ConsumeTraces(ctx, tenant, req); err != nil {
		return nil, status.Error(codes.Internal, "otlp: sink error")
	}
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

type logsService struct {
	collogspb.UnimplementedLogsServiceServer
	sink LogSink
}

// Export ingests an OTLP logs push for the interceptor-resolved tenant.
func (s *logsService) Export(ctx context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	tenant, ok := tenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "otlp: no authenticated tenant")
	}
	if err := scopeLogsToTenant(req, tenant); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	if err := s.sink.ConsumeLogs(ctx, tenant, req); err != nil {
		return nil, status.Error(codes.Internal, "otlp: sink error")
	}
	return &collogspb.ExportLogsServiceResponse{}, nil
}

// --- HTTP handlers (one generic shape, three signals) ---

// signalHTTPHandler is the shared OTLP/HTTP receiver shape: POST protobuf,
// authenticate, bound the body, unmarshal, tenant-scope, consume.
func signalHTTPHandler[Req proto.Message, Resp proto.Message](
	auth Authenticator, maxBytes int64,
	newReq func() Req, newResp func() Resp,
	scope func(Req, string) error,
	consume func(context.Context, string, Req) error,
) http.Handler {
	if maxBytes <= 0 {
		maxBytes = defaultMaxRecvBytes
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tenant, err := auth.Authenticate(bearerFromHeader(r.Header.Get("Authorization")))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req := newReq()
		if err := proto.Unmarshal(body, req); err != nil {
			http.Error(w, "invalid OTLP payload", http.StatusBadRequest)
			return
		}
		if err := scope(req, tenant); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if err := consume(r.Context(), tenant, req); err != nil {
			http.Error(w, "sink error", http.StatusInternalServerError)
			return
		}
		resp, _ := proto.Marshal(newResp())
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(resp)
	})
}

// TracesHTTPHandler is the OTLP/HTTP traces receiver (POST /v1/traces).
func TracesHTTPHandler(auth Authenticator, sink TraceSink, maxBytes int64) http.Handler {
	return signalHTTPHandler(auth, maxBytes,
		func() *coltracepb.ExportTraceServiceRequest { return &coltracepb.ExportTraceServiceRequest{} },
		func() *coltracepb.ExportTraceServiceResponse { return &coltracepb.ExportTraceServiceResponse{} },
		scopeTracesToTenant, sink.ConsumeTraces)
}

// LogsHTTPHandler is the OTLP/HTTP logs receiver (POST /v1/logs).
func LogsHTTPHandler(auth Authenticator, sink LogSink, maxBytes int64) http.Handler {
	return signalHTTPHandler(auth, maxBytes,
		func() *collogspb.ExportLogsServiceRequest { return &collogspb.ExportLogsServiceRequest{} },
		func() *collogspb.ExportLogsServiceResponse { return &collogspb.ExportLogsServiceResponse{} },
		scopeLogsToTenant, sink.ConsumeLogs)
}
