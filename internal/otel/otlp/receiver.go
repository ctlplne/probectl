// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otlp

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	// ARCH-006: register the gRPC gzip decompressor so the OTLP/gRPC receiver
	// can decode gzip-compressed messages (the OTel Collector's otlp exporter
	// gzips by default). Without this blank import the server returns
	// Unimplemented for "gzip" and every default-config push fails.
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/httpbody"
	"github.com/ctlplne/probectl/internal/otel"
)

const defaultMaxRecvBytes = 4 << 20 // 4 MiB

// gRPC server keepalive / lifetime caps for the OTLP/gRPC receiver. Without
// them the server inherits gRPC's permissive defaults: an idle or half-open
// connection is never reaped, a long-lived connection is never cycled, a client
// may ping as fast as it likes, and the stream count is unbounded — so a slow,
// idle, or abusive peer can pin connections and streams open (docs/guardrails.md
// G7-12). Every listener gets bounded keepalive enforcement, connection age, and
// a concurrent-stream ceiling.
const (
	grpcMaxConnectionIdle     = 5 * time.Minute  // reap an idle connection
	grpcMaxConnectionAge      = 30 * time.Minute // cycle a long-lived connection
	grpcMaxConnectionAgeGrace = 1 * time.Minute  // drain grace after the age limit
	grpcKeepaliveMinTime      = 30 * time.Second // reject client pings faster than this
	grpcMaxConcurrentStreams  = 256              // per-connection stream ceiling
	grpcConnectionTimeout     = 20 * time.Second // handshake + setup deadline
)

// grpcKeepalive bundles the gRPC server keepalive / lifetime / stream caps so
// the OTLP/gRPC receiver and its tests share one spec (tests inject a short idle
// to observe the reap without waiting minutes).
type grpcKeepalive struct {
	maxConnectionIdle     time.Duration
	maxConnectionAge      time.Duration
	maxConnectionAgeGrace time.Duration
	minClientPingInterval time.Duration
	maxConcurrentStreams  uint32
	connectionTimeout     time.Duration
}

// defaultGRPCKeepalive is the production keepalive spec (docs/guardrails.md
// G7-12).
func defaultGRPCKeepalive() grpcKeepalive {
	return grpcKeepalive{
		maxConnectionIdle:     grpcMaxConnectionIdle,
		maxConnectionAge:      grpcMaxConnectionAge,
		maxConnectionAgeGrace: grpcMaxConnectionAgeGrace,
		minClientPingInterval: grpcKeepaliveMinTime,
		maxConcurrentStreams:  grpcMaxConcurrentStreams,
		connectionTimeout:     grpcConnectionTimeout,
	}
}

// serverOptions renders the keepalive spec as gRPC server options: bounded
// connection idle/age (KeepaliveParams), a ping-rate floor that permits
// keepalive pings without an active stream (EnforcementPolicy), a concurrent
// stream ceiling, and a handshake/setup timeout.
func (k grpcKeepalive) serverOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     k.maxConnectionIdle,
			MaxConnectionAge:      k.maxConnectionAge,
			MaxConnectionAgeGrace: k.maxConnectionAgeGrace,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             k.minClientPingInterval,
			PermitWithoutStream: true,
		}),
		grpc.MaxConcurrentStreams(k.maxConcurrentStreams),
		grpc.ConnectionTimeout(k.connectionTimeout),
	}
}

// ErrBusUnavailable marks a sink failure meaning the batch was NOT durably
// accepted onto the bus: the broker would reject it (it exceeds the bus's
// configured max message size), the in-flight buffer shed it, or the transport
// is down. The receiver answers the OTLP client with a RETRYABLE status
// (HTTP 503 / gRPC Unavailable) rather than a success, so the client retries
// and telemetry is never acked-then-silently-dropped (ING-13; telemetry loss is
// never silent, docs/guardrails.md G7-2). 503/UNAVAILABLE is the OTLP-spec
// retryable response — the whole point is that the client keeps the batch.
//
// It exists because the default Kafka transport publishes ASYNCHRONOUSLY: its
// Publish returns nil as soon as the record enters the in-flight buffer, long
// before the broker accepts or rejects it. An oversized record is accepted into
// the buffer, Publish returns nil, the sink returns nil, and the push is acked
// 200 — then the broker drops the record. A pre-publish size check against the
// configured bus max closes that window by failing synchronously, before the ack.
var ErrBusUnavailable = errors.New("otlp: bus unavailable — batch not durably accepted; retry")

// busPublish is the oversize + publish-failure gate shared by the three bus
// sinks. A payload larger than maxPublishBytes (0 = unbounded) is rejected
// BEFORE publish with a retryable ErrBusUnavailable, so the async Kafka
// producer can never accept-then-ack a record the broker will drop (ING-13).
// A publish error is likewise wrapped retryable — a record the bus did not take
// must surface to the client as 503/UNAVAILABLE, not as a 200 or a 500.
func busPublish(
	ctx context.Context,
	maxPublishBytes int,
	publish func(ctx context.Context, tenant, entropy string, payload []byte) error,
	tenant, entropy string, payload []byte,
) error {
	if maxPublishBytes > 0 && len(payload) > maxPublishBytes {
		return fmt.Errorf("%w: marshaled batch is %d bytes, over the configured bus max message size of %d bytes",
			ErrBusUnavailable, len(payload), maxPublishBytes)
	}
	if err := publish(ctx, tenant, entropy, payload); err != nil {
		return fmt.Errorf("%w: %v", ErrBusUnavailable, err)
	}
	return nil
}

// sinkHTTPStatus maps a sink/publish error to the HTTP status the OTLP client
// sees. A bus that did not durably accept the batch (ErrBusUnavailable:
// oversize or a publish failure) is RETRYABLE — 503, so the client retries and
// nothing is acked-then-dropped (ING-13). Any other sink error is a 500.
func sinkHTTPStatus(err error) (int, string) {
	if isRetryableSinkErr(err) {
		return http.StatusServiceUnavailable, "bus unavailable"
	}
	return http.StatusInternalServerError, "sink error"
}

// isRetryableSinkErr reports whether a sink/publish error means the batch was
// NOT durably accepted and the OTLP client should RETRY (503 / UNAVAILABLE),
// never a success or a terminal 500 (ING-13, ING-37; telemetry loss is never
// silent, G7-2). It covers the pre-publish/publish-failure wrapper
// (ErrBusUnavailable — which already carries a shed/dropped bus error from
// busPublish) and a bare backpressure drop or context cancel/deadline that
// reached the mapper WITHOUT that wrapper: all mean "the bus did not take it."
func isRetryableSinkErr(err error) bool {
	return errors.Is(err, ErrBusUnavailable) ||
		errors.Is(err, bus.ErrPublishShed) ||
		errors.Is(err, bus.ErrMemoryDropped) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

// sinkGRPCError mirrors sinkHTTPStatus for OTLP/gRPC: Unavailable (retryable)
// when the bus did not accept the batch, Internal otherwise.
func sinkGRPCError(err error) error {
	if isRetryableSinkErr(err) {
		return status.Error(codes.Unavailable, "otlp: bus unavailable")
	}
	return status.Error(codes.Internal, "otlp: sink error")
}

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
// package decoupled from internal/bus. A publish failure surfaces to the OTLP
// client as a retryable 503/UNAVAILABLE (never a success), so a batch the bus
// did not accept is retried, not silently dropped (ING-13).
func NewBusSink(publish func(ctx context.Context, tenant, entropy string, payload []byte) error) Sink {
	return NewBusSinkWithLimit(0, publish)
}

// NewBusSinkWithLimit is NewBusSink with the bus's configured max message size
// (maxPublishBytes; 0 = unbounded). A marshaled batch larger than the limit is
// rejected with a retryable ErrBusUnavailable BEFORE publish, so the default
// asynchronous Kafka producer — whose Publish returns before the broker sees
// the record — can never accept an oversized batch, ack it 200, and have the
// broker drop it afterwards (ING-13).
func NewBusSinkWithLimit(maxPublishBytes int, publish func(ctx context.Context, tenant, entropy string, payload []byte) error) Sink {
	return SinkFunc(func(ctx context.Context, tenant string, req *colmetricspb.ExportMetricsServiceRequest) error {
		payload, err := proto.Marshal(req)
		if err != nil {
			return fmt.Errorf("otlp: marshal ingested metrics: %w", err)
		}
		return busPublish(ctx, maxPublishBytes, publish, tenant, metricsBusEntropy(req), payload)
	})
}

// newGRPCServer builds a TLS-only OTLP/gRPC receiver: the three signal services
// with a pre-decode authenticating tap handle (ING-14), a tenant-scoping unary
// interceptor, and a bounded receive size. It fails closed if no TLS config is
// supplied — the receiver is never plaintext (docs/guardrails.md G7-12).
func newGRPCServer(tlsCfg *tls.Config, auth Authenticator, sinks Sinks, maxRecvBytes int) (*grpc.Server, error) {
	return NewGRPCServerWithFreshness(tlsCfg, auth, sinks, maxRecvBytes, nil)
}

// NewGRPCServerWithFreshness builds an OTLP/gRPC receiver that also enforces
// the optional signed timestamp+nonce envelope when freshness is enabled. It
// applies the production keepalive / connection-lifetime caps (G7-12).
func NewGRPCServerWithFreshness(tlsCfg *tls.Config, auth Authenticator, sinks Sinks, maxRecvBytes int, freshness *FreshnessVerifier) (*grpc.Server, error) {
	return newGRPCServerWithKeepalive(tlsCfg, auth, sinks, maxRecvBytes, freshness, defaultGRPCKeepalive())
}

// newGRPCServerWithKeepalive is the internal seam that builds the OTLP/gRPC
// receiver with an explicit keepalive spec. Production goes through
// defaultGRPCKeepalive(); tests inject a short idle to observe idle-connection
// reaping without waiting minutes.
func newGRPCServerWithKeepalive(tlsCfg *tls.Config, auth Authenticator, sinks Sinks, maxRecvBytes int, freshness *FreshnessVerifier, ka grpcKeepalive) (*grpc.Server, error) {
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
	opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		// Authenticate at the transport layer, BEFORE the gRPC runtime reads,
		// decompresses, or proto-decodes the request body: an unauthenticated
		// caller is rejected without any decode, so a decompression bomb from an
		// unauthenticated peer does no decoding (ING-14, docs/guardrails.md G7-12).
		grpc.InTapHandle(authTapHandle(auth)),
		grpc.UnaryInterceptor(authUnaryInterceptorWithFreshness(auth, freshness)),
		grpc.MaxRecvMsgSize(maxRecvBytes),
	}
	// Bound keepalive, connection age/idle, and concurrent streams so a slow or
	// idle peer cannot pin connections and streams open (G7-12).
	opts = append(opts, ka.serverOptions()...)
	srv := grpc.NewServer(opts...)
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
	if err := validateMetricPointTypes(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.sink.ConsumeMetrics(ctx, tenant, req); err != nil {
		return nil, sinkGRPCError(err)
	}
	return &colmetricspb.ExportMetricsServiceResponse{}, nil
}

// MetricsHTTPHandler is the OTLP/HTTP metrics receiver: POST an
// ExportMetricsServiceRequest (protobuf), authenticated + tenant-scoped, with a
// bounded body (untrusted input). The caller must serve it over TLS.
func MetricsHTTPHandler(auth Authenticator, sink Sink, maxBytes int64) http.Handler {
	return MetricsHTTPHandlerWithFreshness(auth, sink, maxBytes, nil)
}

// MetricsHTTPHandlerWithFreshness builds the OTLP/HTTP metrics receiver with
// optional application-level replay protection.
func MetricsHTTPHandlerWithFreshness(auth Authenticator, sink Sink, maxBytes int64, freshness *FreshnessVerifier) http.Handler {
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
		if freshness.Enabled() {
			if err := freshness.VerifyHTTP(r, tenant, body); err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
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
		if err := validateMetricPointTypes(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := sink.ConsumeMetrics(r.Context(), tenant, &req); err != nil {
			code, msg := sinkHTTPStatus(err)
			http.Error(w, msg, code)
			return
		}
		resp, _ := proto.Marshal(&colmetricspb.ExportMetricsServiceResponse{})
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(resp)
	})
}

// validateMetricPointTypes makes the receiver's TSDB materialization boundary
// explicit. Gauge, sum, and explicit-bucket histogram points are supported by
// the downstream converter. Summary and exponential-histogram points are not:
// reject the whole push at the authenticated edge so a collector receives a
// documented error instead of a success followed by a downstream silent drop.
// Tenant scoping MUST run before this check (tenant is the outer boundary).
func validateMetricPointTypes(req *colmetricspb.ExportMetricsServiceRequest) error {
	for resourceIndex, rm := range req.GetResourceMetrics() {
		for scopeIndex, sm := range rm.GetScopeMetrics() {
			for metricIndex, metric := range sm.GetMetrics() {
				kind := ""
				switch metric.GetData().(type) {
				case *metricspb.Metric_Gauge, *metricspb.Metric_Sum, *metricspb.Metric_Histogram:
					continue
				case *metricspb.Metric_Summary:
					kind = "summary"
				case *metricspb.Metric_ExponentialHistogram:
					kind = "exponential_histogram"
				default:
					kind = "unspecified"
				}
				return fmt.Errorf("otlp: unsupported metric point type %q at resource[%d].scope[%d].metric[%d] (%q)",
					kind, resourceIndex, scopeIndex, metricIndex, metric.GetName())
			}
		}
	}
	return nil
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
		return httpbody.ReadLimited(gz, maxBytes)
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
