// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"bytes"
	"context"
	"testing"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
)

// --- helpers ---------------------------------------------------------------

func kvStr(key, val string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: key, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: val}}}
}

func attrMap(kvs []*commonpb.KeyValue) map[string]string {
	out := map[string]string{}
	for _, kv := range kvs {
		if sv, ok := kv.GetValue().GetValue().(*commonpb.AnyValue_StringValue); ok {
			out[kv.GetKey()] = sv.StringValue
		}
	}
	return out
}

// captureTraces/Logs/Metrics record the last request the consumer forwarded, so
// the test inspects the ACTUAL bytes that would reach the external collector —
// the real export entry point (handle), never a mock of the redaction itself.
type captureSignals struct {
	metrics, traces, logs int
	lastTrace             *coltracepb.ExportTraceServiceRequest
	lastLog               *collogspb.ExportLogsServiceRequest
	lastMetric            *colmetricspb.ExportMetricsServiceRequest
}

func (c *captureSignals) ExportMetrics(_ context.Context, r *colmetricspb.ExportMetricsServiceRequest) error {
	c.metrics++
	c.lastMetric = r
	return nil
}
func (c *captureSignals) ExportTraces(_ context.Context, r *coltracepb.ExportTraceServiceRequest) error {
	c.traces++
	c.lastTrace = r
	return nil
}
func (c *captureSignals) ExportLogs(_ context.Context, r *collogspb.ExportLogsServiceRequest) error {
	c.logs++
	c.lastLog = r
	return nil
}

// TestOTLPTraceExportRedactsToStoredForm proves the RTP-06 redaction acceptance
// on the REAL export entry point: a secret and an Authorization header present in
// a raw span are ABSENT from the payload forwarded to the collector, and the
// exported span name/attributes equal the redacted form the STORAGE path would
// persist. RED on the pre-fix code (the re-export forwarded the span verbatim).
func TestOTLPTraceExportRedactsToStoredForm(t *testing.T) {
	const tenant = "tenant-a"
	const secret = "sk-live_TOPSECRETtoken0123456789"
	raw := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			ScopeSpans: []*tracepb.ScopeSpans{{
				Spans: []*tracepb.Span{{
					Name: "authorize user with " + secret,
					Attributes: []*commonpb.KeyValue{
						kvStr("http.request.header.authorization", "Bearer "+secret),
						kvStr("db.statement", "select 1 -- password="+secret),
						kvStr("http.method", "GET"),
					},
					Status: &tracepb.Status{Message: "token " + secret + " rejected"},
				}},
			}},
		}},
	}

	// The storage path's redacted form for the SAME raw input.
	storedSpans := convertSpansWithContext(context.Background(), proto.Clone(raw).(*coltracepb.ExportTraceServiceRequest), tenant)
	if len(storedSpans) != 1 {
		t.Fatalf("stored spans = %d, want 1", len(storedSpans))
	}

	capt := &captureSignals{}
	c := NewOTLPTraceExportConsumer(bus.NewMemory(), capt, testLogger())
	if err := c.handle(context.Background(), bus.Message{Key: []byte(tenant), Value: mustMarshal(t, raw)}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if capt.traces != 1 || capt.lastTrace == nil {
		t.Fatalf("one handle must forward exactly one trace export (got %d)", capt.traces)
	}

	// 1) The raw secret must NOT survive anywhere in the exported payload.
	blob := mustMarshal(t, capt.lastTrace)
	if bytes.Contains(blob, []byte("TOPSECRET")) {
		t.Fatalf("RTP-06: the raw secret egressed in the re-exported span payload")
	}

	// 2) The exported span name + attributes equal the redacted stored form.
	got := capt.lastTrace.GetResourceSpans()[0].GetScopeSpans()[0].GetSpans()[0]
	if got.GetName() != storedSpans[0].Name {
		t.Fatalf("exported span name %q != stored redacted form %q", got.GetName(), storedSpans[0].Name)
	}
	gotAttrs := attrMap(got.GetAttributes())
	for _, k := range []string{"http.request.header.authorization", "db.statement"} {
		if gotAttrs[k] != storedSpans[0].Attrs[k] {
			t.Fatalf("exported attr %q = %q, stored redacted form = %q", k, gotAttrs[k], storedSpans[0].Attrs[k])
		}
		if gotAttrs[k] == "" {
			t.Fatalf("expected a redacted value for %q, got empty", k)
		}
	}
}

// TestOTLPLogExportRedactsToStoredForm is the log counterpart: a secret in a log
// body / attribute is masked to the stored form before egress.
func TestOTLPLogExportRedactsToStoredForm(t *testing.T) {
	const tenant = "tenant-a"
	const secret = "sk-live_LOGSECRETtoken987654321"
	raw := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			ScopeLogs: []*logspb.ScopeLogs{{
				LogRecords: []*logspb.LogRecord{{
					Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "auth header Authorization: Bearer " + secret}},
					Attributes: []*commonpb.KeyValue{
						kvStr("api_key", secret),
						kvStr("http.route", "/v1/login"),
					},
				}},
			}},
		}},
	}

	storedLogs := convertLogsWithContext(context.Background(), proto.Clone(raw).(*collogspb.ExportLogsServiceRequest), tenant)
	if len(storedLogs) != 1 {
		t.Fatalf("stored logs = %d, want 1", len(storedLogs))
	}

	capt := &captureSignals{}
	c := NewOTLPLogExportConsumer(bus.NewMemory(), capt, testLogger())
	if err := c.handle(context.Background(), bus.Message{Key: []byte(tenant), Value: mustMarshal(t, raw)}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if capt.logs != 1 || capt.lastLog == nil {
		t.Fatalf("one handle must forward exactly one log export (got %d)", capt.logs)
	}
	blob := mustMarshal(t, capt.lastLog)
	if bytes.Contains(blob, []byte("LOGSECRET")) {
		t.Fatalf("RTP-06: the raw secret egressed in the re-exported log payload")
	}
	got := capt.lastLog.GetResourceLogs()[0].GetScopeLogs()[0].GetLogRecords()[0]
	gotBody := got.GetBody().GetStringValue()
	if gotBody != storedLogs[0].Body {
		t.Fatalf("exported log body %q != stored redacted form %q", gotBody, storedLogs[0].Body)
	}
	if v := attrMap(got.GetAttributes())["api_key"]; v != storedLogs[0].Attrs["api_key"] || v == "" {
		t.Fatalf("exported api_key attr %q != stored redacted form %q", v, storedLogs[0].Attrs["api_key"])
	}
}

// TestOTLPMetricExportMasksSecretAttr proves a secret in a metric attribute does
// not egress on the re-export path.
func TestOTLPMetricExportMasksSecretAttr(t *testing.T) {
	const tenant = "tenant-a"
	const secret = "sk-live_METRICSECRETtoken000111"
	raw := &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			ScopeMetrics: []*metricspb.ScopeMetrics{{
				Metrics: []*metricspb.Metric{{
					Name: "http.server.requests",
					Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{
						Attributes: []*commonpb.KeyValue{kvStr("http.request.header.authorization", "Bearer "+secret)},
						Value:      &metricspb.NumberDataPoint_AsInt{AsInt: 1},
					}}}},
				}},
			}},
		}},
	}
	capt := &captureSignals{}
	c := NewOTLPExportConsumer(bus.NewMemory(), capt, testLogger())
	if err := c.handle(context.Background(), bus.Message{Key: []byte(tenant), Value: mustMarshal(t, raw)}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if capt.metrics != 1 || capt.lastMetric == nil {
		t.Fatalf("one handle must forward exactly one metric export (got %d)", capt.metrics)
	}
	if bytes.Contains(mustMarshal(t, capt.lastMetric), []byte("METRICSECRET")) {
		t.Fatalf("RTP-06: the raw secret egressed in the re-exported metric payload")
	}
}

// TestOTLPExportPerTenantRoutingIsolation proves the RTP-06 tenant-isolation
// acceptance: with a per-tenant router, a tenant's telemetry reaches ONLY that
// tenant's collector, never another tenant's; and a tenant with no configured
// endpoint is dropped closed (never forwarded to anyone). Exercised on the real
// consumer entry point (handleLane) for all four export lanes.
func TestOTLPExportPerTenantRoutingIsolation(t *testing.T) {
	collA := &captureSignals{}
	collB := &captureSignals{}
	router := NewTenantExportRouter().Add("tenant-a", collA).Add("tenant-b", collB)

	tracePayload := mustMarshal(t, &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{}}})
	logPayload := mustMarshal(t, &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{}}})
	metricPayload := mustMarshal(t, &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{}}})

	// Traces: tenant-a's lane reaches only collector A.
	tc := NewOTLPTraceExportConsumer(bus.NewMemory(), nil, testLogger()).WithTenantRouter(router)
	if err := tc.handleLane(context.Background(), bus.Message{Value: tracePayload}, "tenant-a"); err != nil {
		t.Fatalf("trace handleLane: %v", err)
	}
	if collA.traces != 1 || collB.traces != 0 {
		t.Fatalf("tenant-a traces: A=%d B=%d, want 1/0 (cross-tenant leak)", collA.traces, collB.traces)
	}
	// A tenant with no endpoint is dropped closed — neither collector sees it.
	if err := tc.handleLane(context.Background(), bus.Message{Value: tracePayload}, "tenant-unknown"); err != nil {
		t.Fatalf("trace handleLane (unknown): %v", err)
	}
	if collA.traces != 1 || collB.traces != 0 {
		t.Fatalf("unconfigured tenant must not reach any collector: A=%d B=%d", collA.traces, collB.traces)
	}
	if tc.droppedCount() != 1 {
		t.Fatalf("unconfigured tenant trace must be dropped closed: dropped=%d, want 1", tc.droppedCount())
	}

	// Logs: tenant-b's lane reaches only collector B.
	lc := NewOTLPLogExportConsumer(bus.NewMemory(), nil, testLogger()).WithTenantRouter(router)
	if err := lc.handleLane(context.Background(), bus.Message{Value: logPayload}, "tenant-b"); err != nil {
		t.Fatalf("log handleLane: %v", err)
	}
	if collB.logs != 1 || collA.logs != 0 {
		t.Fatalf("tenant-b logs: A=%d B=%d, want 0/1 (cross-tenant leak)", collA.logs, collB.logs)
	}
	if err := lc.handleLane(context.Background(), bus.Message{Value: logPayload}, "tenant-unknown"); err != nil {
		t.Fatalf("log handleLane (unknown): %v", err)
	}
	if collA.logs != 0 || collB.logs != 1 || lc.droppedCount() != 1 {
		t.Fatalf("unconfigured tenant log must be dropped closed: A=%d B=%d dropped=%d", collA.logs, collB.logs, lc.droppedCount())
	}

	// Metrics: tenant-a's lane reaches only collector A.
	mc := NewOTLPExportConsumer(bus.NewMemory(), nil, testLogger()).WithTenantRouter(router)
	if err := mc.handleLane(context.Background(), bus.Message{Value: metricPayload}, "tenant-a"); err != nil {
		t.Fatalf("metric handleLane: %v", err)
	}
	if collA.metrics != 1 || collB.metrics != 0 {
		t.Fatalf("tenant-a metrics: A=%d B=%d, want 1/0 (cross-tenant leak)", collA.metrics, collB.metrics)
	}
	if err := mc.handleLane(context.Background(), bus.Message{Value: metricPayload}, "tenant-unknown"); err != nil {
		t.Fatalf("metric handleLane (unknown): %v", err)
	}
	if collA.metrics != 1 || collB.metrics != 0 || mc.droppedCount() != 1 {
		t.Fatalf("unconfigured tenant metric must be dropped closed: A=%d B=%d dropped=%d", collA.metrics, collB.metrics, mc.droppedCount())
	}

	// Result (RTP-07 self-observability) export routes per tenant too: tenant-b's
	// probe result reaches only collector B, and an unconfigured tenant is dropped.
	rc := NewResultOTLPExportConsumer(bus.NewMemory(), nil, testLogger()).WithTenantRouter(router)
	resB := mustMarshal(t, &resultv1.Result{TenantId: "tenant-b", Success: true})
	if err := rc.handleLane(context.Background(), bus.Message{Value: resB}, "tenant-b"); err != nil {
		t.Fatalf("result handleLane: %v", err)
	}
	if collB.metrics != 1 || collA.metrics != 1 {
		t.Fatalf("tenant-b probe result must reach only collector B: A=%d B=%d", collA.metrics, collB.metrics)
	}
	resC := mustMarshal(t, &resultv1.Result{TenantId: "tenant-unknown", Success: true})
	if err := rc.handleLane(context.Background(), bus.Message{Value: resC}, "tenant-unknown"); err != nil {
		t.Fatalf("result handleLane (unknown): %v", err)
	}
	if rc.droppedCount() != 1 {
		t.Fatalf("unconfigured tenant probe result must be dropped closed: dropped=%d, want 1", rc.droppedCount())
	}
}

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
