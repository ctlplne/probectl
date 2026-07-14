// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build isolation

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
	"github.com/imfeelingtheagi/probectl/internal/otel"
	"github.com/imfeelingtheagi/probectl/internal/otel/otlp"
	"github.com/imfeelingtheagi/probectl/internal/store/otelstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

func TestOTLPServedPathIsolationAllSignals(t *testing.T) {
	const (
		tenantA = "tenant-a"
		tenantB = "tenant-b"
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := bus.NewMemory()
	defer b.Close()
	metricsStore := tsdb.NewMemory()
	signalsStore := otelstore.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	go func() { _ = NewOTLPConsumer(b, metricsStore, log).Run(ctx) }()
	go func() { _ = NewOTLPTraceConsumer(b, signalsStore, log).Run(ctx) }()
	go func() { _ = NewOTLPLogConsumer(b, signalsStore, log).Run(ctx) }()
	waitForOTLPSubscribers(ctx, t, b)

	sinks := otlpIsolationSinks(b)
	authA := otlp.NewTokenAuthenticator(map[string]string{"tok-a": tenantA})
	authB := otlp.NewTokenAuthenticator(map[string]string{"tok-b": tenantB})
	now := time.Now().UTC().Truncate(time.Microsecond)

	// No credential means no tenant at the edge: fail closed before storage.
	if code := postOTLPIsolation(t, otlp.MetricsHTTPHandler(authA, sinks.Metrics, 0), "", metricReq("", "no-auth", 1, now)); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated metrics push = %d, want 401", code)
	}
	if code := postOTLPIsolation(t, otlp.TracesHTTPHandler(authA, sinks.Traces, 0), "", traceReqIsolation("", "no-auth", now, 0x10)); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated trace push = %d, want 401", code)
	}
	if code := postOTLPIsolation(t, otlp.LogsHTTPHandler(authA, sinks.Logs, 0), "", logReqIsolation("", "no-auth", now, 0x20)); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated log push = %d, want 401", code)
	}

	// Authenticated as A but resource claims B: fail closed and never restamp.
	if code := postOTLPIsolation(t, otlp.MetricsHTTPHandler(authA, sinks.Metrics, 0), "tok-a", metricReq(tenantB, "forged", 2, now)); code != http.StatusForbidden {
		t.Fatalf("cross-tenant metrics push = %d, want 403", code)
	}
	if code := postOTLPIsolation(t, otlp.TracesHTTPHandler(authA, sinks.Traces, 0), "tok-a", traceReqIsolation(tenantB, "forged", now, 0x30)); code != http.StatusForbidden {
		t.Fatalf("cross-tenant trace push = %d, want 403", code)
	}
	if code := postOTLPIsolation(t, otlp.LogsHTTPHandler(authA, sinks.Logs, 0), "tok-a", logReqIsolation(tenantB, "forged", now, 0x40)); code != http.StatusForbidden {
		t.Fatalf("cross-tenant log push = %d, want 403", code)
	}

	// Missing resource tenant is safe only because the edge credential supplies
	// tenant A; the receiver stamps it before bus/persistence.
	if code := postOTLPIsolation(t, otlp.MetricsHTTPHandler(authA, sinks.Metrics, 0), "tok-a", metricReq("", "checkout-a", 11, now)); code != http.StatusOK {
		t.Fatalf("unstamped tenant-A metrics push = %d, want 200", code)
	}
	if code := postOTLPIsolation(t, otlp.TracesHTTPHandler(authA, sinks.Traces, 0), "tok-a", traceReqIsolation("", "checkout-a", now, 0x50)); code != http.StatusOK {
		t.Fatalf("unstamped tenant-A trace push = %d, want 200", code)
	}
	if code := postOTLPIsolation(t, otlp.LogsHTTPHandler(authA, sinks.Logs, 0), "tok-a", logReqIsolation("", "checkout-a", now, 0x60)); code != http.StatusOK {
		t.Fatalf("unstamped tenant-A log push = %d, want 200", code)
	}

	if code := postOTLPIsolation(t, otlp.MetricsHTTPHandler(authB, sinks.Metrics, 0), "tok-b", metricReq(tenantB, "checkout-b", 22, now)); code != http.StatusOK {
		t.Fatalf("tenant-B metrics push = %d, want 200", code)
	}
	if code := postOTLPIsolation(t, otlp.TracesHTTPHandler(authB, sinks.Traces, 0), "tok-b", traceReqIsolation(tenantB, "checkout-b", now, 0x70)); code != http.StatusOK {
		t.Fatalf("tenant-B trace push = %d, want 200", code)
	}
	if code := postOTLPIsolation(t, otlp.LogsHTTPHandler(authB, sinks.Logs, 0), "tok-b", logReqIsolation(tenantB, "checkout-b", now, 0x80)); code != http.StatusOK {
		t.Fatalf("tenant-B log push = %d, want 200", code)
	}
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	assertOTLPTenantRows(t, metricsStore, signalsStore, tenantA, "checkout-a", 11)
	assertOTLPTenantRows(t, metricsStore, signalsStore, tenantB, "checkout-b", 22)
	assertNoOTLPTenantRows(t, metricsStore, signalsStore, "tenant-c", "checkout-a")
	assertNoOTLPTenantRows(t, metricsStore, signalsStore, tenantA, "checkout-b")
	assertNoOTLPTenantRows(t, metricsStore, signalsStore, tenantB, "checkout-a")
	assertNoOTLPTenantRows(t, metricsStore, signalsStore, tenantA, "forged")
	assertNoOTLPTenantRows(t, metricsStore, signalsStore, tenantB, "forged")
}

func waitForOTLPSubscribers(ctx context.Context, t *testing.T, b *bus.Memory) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for _, topic := range []string{bus.OTLPMetricsTopic, bus.OTLPTracesTopic, bus.OTLPLogsTopic} {
		if !b.WaitForSubscribers(waitCtx, topic, 1) {
			t.Fatalf("OTLP subscriber for %s did not register", topic)
		}
	}
}

func otlpIsolationSinks(b bus.Bus) otlp.Sinks {
	return otlp.Sinks{
		Metrics: otlp.NewBusSink(func(ctx context.Context, tenant, entropy string, payload []byte) error {
			return b.Publish(ctx, bus.OTLPMetricsTopic, bus.TenantKey(tenant, entropy), payload)
		}),
		Traces: otlp.NewBusTraceSink(func(ctx context.Context, tenant, entropy string, payload []byte) error {
			return b.Publish(ctx, bus.OTLPTracesTopic, bus.TenantKey(tenant, entropy), payload)
		}),
		Logs: otlp.NewBusLogSink(func(ctx context.Context, tenant, entropy string, payload []byte) error {
			return b.Publish(ctx, bus.OTLPLogsTopic, bus.TenantKey(tenant, entropy), payload)
		}),
	}
}

func metricReq(tenant, service string, value float64, ts time.Time) *colmetricspb.ExportMetricsServiceRequest {
	return &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: resourceFor(tenant, service),
		ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
			Name: "isolation.requests",
			Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{
				TimeUnixNano: uint64(ts.UnixNano()),
				Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: value},
			}}}},
		}}}},
	}}}
}

func traceReqIsolation(tenant, service string, ts time.Time, seed byte) *coltracepb.ExportTraceServiceRequest {
	return &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: resourceFor(tenant, service),
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{
			TraceId:           bytes.Repeat([]byte{seed}, 16),
			SpanId:            bytes.Repeat([]byte{seed + 1}, 8),
			Name:              "GET /" + service,
			Kind:              tracepb.Span_SPAN_KIND_SERVER,
			StartTimeUnixNano: uint64(ts.UnixNano()),
			EndTimeUnixNano:   uint64(ts.Add(10 * time.Millisecond).UnixNano()),
		}}}},
	}}}
}

func logReqIsolation(tenant, service string, ts time.Time, seed byte) *collogspb.ExportLogsServiceRequest {
	return &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: resourceFor(tenant, service),
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
			TimeUnixNano:   uint64(ts.UnixNano()),
			SeverityNumber: logspb.SeverityNumber_SEVERITY_NUMBER_INFO,
			SeverityText:   "INFO",
			Body:           &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "log " + service}},
			TraceId:        bytes.Repeat([]byte{seed}, 16),
			SpanId:         bytes.Repeat([]byte{seed + 1}, 8),
		}}}},
	}}}
}

func resourceFor(tenant, service string) *resourcepb.Resource {
	attrs := []*commonpb.KeyValue{kv("service.name", service)}
	if tenant != "" {
		attrs = append(attrs, kv(otel.AttrTenantID, tenant))
	}
	return &resourcepb.Resource{Attributes: attrs}
}

func postOTLPIsolation(t *testing.T, h http.Handler, token string, req proto.Message) int {
	t.Helper()
	body, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func assertOTLPTenantRows(t *testing.T, metricsStore *tsdb.Memory, signalsStore otelstore.Store, tenant, service string, wantMetric float64) {
	t.Helper()
	metric := metricsStore.Query("probectl_otlp_isolation_requests", map[string]string{"tenant_id": tenant, "service_name": service})
	if len(metric) != 1 || metric[0].Value != wantMetric {
		t.Fatalf("%s metrics for %s = %+v, want one value %.0f", tenant, service, metric, wantMetric)
	}
	spans, err := signalsStore.QuerySpans(context.Background(), tenant, otelstore.SpanQuery{Service: service})
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 1 || spans[0].TenantID != tenant {
		t.Fatalf("%s spans for %s = %+v, want one tenant-scoped span", tenant, service, spans)
	}
	logs, err := signalsStore.QueryLogs(context.Background(), tenant, otelstore.LogQuery{Service: service})
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].TenantID != tenant {
		t.Fatalf("%s logs for %s = %+v, want one tenant-scoped log", tenant, service, logs)
	}
}

func assertNoOTLPTenantRows(t *testing.T, metricsStore *tsdb.Memory, signalsStore otelstore.Store, tenant, service string) {
	t.Helper()
	if got := metricsStore.Query("probectl_otlp_isolation_requests", map[string]string{"tenant_id": tenant, "service_name": service}); len(got) != 0 {
		t.Fatalf("%s unexpectedly saw metrics for %s: %+v", tenant, service, got)
	}
	if got, err := signalsStore.QuerySpans(context.Background(), tenant, otelstore.SpanQuery{Service: service}); err != nil || len(got) != 0 {
		t.Fatalf("%s unexpectedly saw spans for %s: err=%v rows=%+v", tenant, service, err, got)
	}
	if got, err := signalsStore.QueryLogs(context.Background(), tenant, otelstore.LogQuery{Service: service}); err != nil || len(got) != 0 {
		t.Fatalf("%s unexpectedly saw logs for %s: err=%v rows=%+v", tenant, service, err, got)
	}
}
