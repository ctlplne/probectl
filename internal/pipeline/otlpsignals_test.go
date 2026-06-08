package pipeline

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/otel/otlp"
	"github.com/imfeelingtheagi/probectl/internal/store/otelstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// The Sprint 22 CI gate (ARCH-001): ALL THREE OTLP signals round-trip —
// authenticated HTTP receiver → tenant-scoped bus topic → consumer → store →
// tenant-scoped query. The HTTP handlers here are EXACTLY what an OTel
// Collector's otlphttp exporter posts to (ARCH-006), so this also pins the
// Collector-facing wire contract.
func TestOTLPThreeSignalRoundTrip(t *testing.T) {
	const tenant = "t-otlp"
	auth := otlp.NewTokenAuthenticator(map[string]string{"tok-1": tenant})
	b := bus.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Stores + consumers (the production wiring shape from main.go).
	tsdbStore := tsdb.NewMemory()
	signals := otelstore.NewMemory()
	mc := NewOTLPConsumer(b, tsdbStore, log)
	tc := NewOTLPTraceConsumer(b, signals, log)
	lc := NewOTLPLogConsumer(b, signals, log)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = mc.Run(ctx) }()
	go func() { _ = tc.Run(ctx) }()
	go func() { _ = lc.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)

	// The receiver sinks publish to the per-signal topics (tenant-keyed).
	sinks := otlp.Sinks{
		Metrics: otlp.NewBusSink(func(ctx context.Context, tenant string, payload []byte) error {
			return b.Publish(ctx, bus.OTLPMetricsTopic, []byte(tenant), payload)
		}),
		Traces: otlp.NewBusTraceSink(func(ctx context.Context, tenant string, payload []byte) error {
			return b.Publish(ctx, bus.OTLPTracesTopic, []byte(tenant), payload)
		}),
		Logs: otlp.NewBusLogSink(func(ctx context.Context, tenant string, payload []byte) error {
			return b.Publish(ctx, bus.OTLPLogsTopic, []byte(tenant), payload)
		}),
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	res := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
		Key: "service.name", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "checkout"}},
	}}}

	// --- metrics ---
	mreq := &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: res,
		ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
			Name: "http_requests",
			Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{
				TimeUnixNano: uint64(now.UnixNano()),
				Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: 42},
			}}}},
		}}}},
	}}}
	postSignal(t, otlp.MetricsHTTPHandler(auth, sinks.Metrics, 0), mreq)

	// --- traces ---
	traceID := bytes.Repeat([]byte{0xAB}, 16)
	spanID := bytes.Repeat([]byte{0xCD}, 8)
	treq := &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: res,
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{
			TraceId: traceID, SpanId: spanID, Name: "GET /cart",
			Kind:              tracepb.Span_SPAN_KIND_SERVER,
			StartTimeUnixNano: uint64(now.UnixNano()),
			EndTimeUnixNano:   uint64(now.Add(150 * time.Millisecond).UnixNano()),
			Status:            &tracepb.Status{Code: tracepb.Status_STATUS_CODE_ERROR},
			Attributes: []*commonpb.KeyValue{{
				Key: "http.route", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "/cart"}},
			}},
		}}}},
	}}}
	postSignal(t, otlp.TracesHTTPHandler(auth, sinks.Traces, 0), treq)

	// --- logs ---
	lreq := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: res,
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
			TimeUnixNano:   uint64(now.UnixNano()),
			SeverityNumber: logspb.SeverityNumber_SEVERITY_NUMBER_ERROR,
			SeverityText:   "ERROR",
			Body:           &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "checkout failed: card declined"}},
			TraceId:        traceID, SpanId: spanID,
		}}}},
	}}}
	postSignal(t, otlp.LogsHTTPHandler(auth, sinks.Logs, 0), lreq)

	// Settle: all three consumers stored their signal.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		spans, logs := signals.Len(tenant)
		if mc.Consumed() >= 1 && spans >= 1 && logs >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// --- queryable, tenant-scoped ---
	series := tsdbStore.Query("probectl_otlp_http_requests", map[string]string{"tenant_id": tenant})
	if len(series) != 1 || series[0].Value != 42 {
		t.Fatalf("metrics signal must round-trip to a queryable tenant-labeled series: %+v", series)
	}

	spans, err := signals.QuerySpans(context.Background(), tenant, otelstore.SpanQuery{Service: "checkout"})
	if err != nil || len(spans) != 1 {
		t.Fatalf("traces signal must round-trip: %v %+v", err, spans)
	}
	sp := spans[0]
	if sp.TenantID != tenant || sp.Name != "GET /cart" || sp.Kind != "server" || sp.StatusCode != "error" {
		t.Fatalf("span fields wrong: %+v", sp)
	}
	if sp.TraceID != "abababababababababababababababab" || sp.Duration != 150*time.Millisecond {
		t.Fatalf("span identity/duration wrong: %+v", sp)
	}
	if sp.Attrs["http.route"] != "/cart" {
		t.Fatalf("span attrs must survive (bounded): %+v", sp.Attrs)
	}

	logs, err := signals.QueryLogs(context.Background(), tenant, otelstore.LogQuery{TraceID: sp.TraceID, MinSeverity: 17})
	if err != nil || len(logs) != 1 {
		t.Fatalf("logs signal must round-trip (trace-correlated, severity-floored): %v %+v", err, logs)
	}
	if logs[0].Body != "checkout failed: card declined" || logs[0].Service != "checkout" {
		t.Fatalf("log fields wrong: %+v", logs[0])
	}

	// Cross-tenant scoping: another tenant sees NOTHING.
	if got, _ := signals.QuerySpans(context.Background(), "t-other", otelstore.SpanQuery{}); len(got) != 0 {
		t.Fatalf("cross-tenant span leak: %+v", got)
	}
	if got, _ := signals.QueryLogs(context.Background(), "t-other", otelstore.LogQuery{}); len(got) != 0 {
		t.Fatalf("cross-tenant log leak: %+v", got)
	}
}

// A push whose resource names ANOTHER tenant is rejected at the receiver for
// traces and logs exactly like metrics (the tenant-isolation contract).
func TestOTLPTraceLogTenantMismatchRejected(t *testing.T) {
	auth := otlp.NewTokenAuthenticator(map[string]string{"tok-1": "t1"})
	denySink := otlp.Sinks{
		Metrics: otlp.SinkFunc(func(context.Context, string, *colmetricspb.ExportMetricsServiceRequest) error { return nil }),
		Traces: otlp.TraceSinkFunc(func(context.Context, string, *coltracepb.ExportTraceServiceRequest) error {
			t.Fatal("a cross-tenant trace push must never reach the sink")
			return nil
		}),
		Logs: otlp.LogSinkFunc(func(context.Context, string, *collogspb.ExportLogsServiceRequest) error {
			t.Fatal("a cross-tenant log push must never reach the sink")
			return nil
		}),
	}
	foreign := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
		Key: "probectl.tenant.id", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "t-other"}},
	}}}

	treq := &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{Resource: foreign}}}
	if code := postSignalCode(t, otlp.TracesHTTPHandler(auth, denySink.Traces, 0), treq); code != 403 {
		t.Fatalf("cross-tenant trace push: want 403, got %d", code)
	}
	lreq := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{Resource: foreign}}}
	if code := postSignalCode(t, otlp.LogsHTTPHandler(auth, denySink.Logs, 0), lreq); code != 403 {
		t.Fatalf("cross-tenant log push: want 403, got %d", code)
	}
}

// postSignal POSTs a protobuf export request through the real HTTP handler
// (bearer-authenticated) and asserts 200.
func postSignal(t *testing.T, h http.Handler, req proto.Message) {
	t.Helper()
	if code := postSignalCode(t, h, req); code != http.StatusOK {
		t.Fatalf("OTLP push: want 200, got %d", code)
	}
}

// postSignalCode POSTs and returns the status code.
func postSignalCode(t *testing.T, h http.Handler, req proto.Message) int {
	t.Helper()
	body, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer tok-1")
	r.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}
