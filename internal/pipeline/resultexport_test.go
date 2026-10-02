// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/otel/otlp"
)

// newOTLPMetricsCollector stands up a real HTTP endpoint that decodes the OTLP
// metrics the production exporter POSTs. It is the actual export path (real
// otlp.NewHTTPExporter → real HTTP server), never a mock (RTP-07).
func newOTLPMetricsCollector(t *testing.T) (string, <-chan *colmetricspb.ExportMetricsServiceRequest) {
	t.Helper()
	received := make(chan *colmetricspb.ExportMetricsServiceRequest, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		var req colmetricspb.ExportMetricsServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		received <- &req
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, received
}

// probeSuccessValue returns the probectl.probe.success gauge value in the export
// request, if present.
func probeSuccessValue(req *colmetricspb.ExportMetricsServiceRequest) (float64, bool) {
	for _, rm := range req.GetResourceMetrics() {
		for _, sm := range rm.GetScopeMetrics() {
			for _, m := range sm.GetMetrics() {
				if m.GetName() != "probectl.probe.success" {
					continue
				}
				for _, dp := range m.GetGauge().GetDataPoints() {
					return dp.GetAsDouble(), true
				}
			}
		}
	}
	return 0, false
}

// exportedTenant returns the probectl.tenant.id resource attribute on the first
// resource of the export request.
func exportedTenant(req *colmetricspb.ExportMetricsServiceRequest) string {
	for _, rm := range req.GetResourceMetrics() {
		for _, kv := range rm.GetResource().GetAttributes() {
			if kv.GetKey() == "probectl.tenant.id" {
				return kv.GetValue().GetStringValue()
			}
		}
	}
	return ""
}

// TestResultOTLPExportReachesCollector proves the RTP-07 acceptance: with OTLP
// export wired, probectl.probe.success for a canary result reaches the collector
// within one flush (one handle() == one export). It also pins G7-1: the exported
// tenant is the authoritative bus-key tenant, and a result whose payload tenant
// is spoofed to differ from the bus key is dropped, never re-attributed onto the
// collector.
func TestResultOTLPExportReachesCollector(t *testing.T) {
	url, received := newOTLPMetricsCollector(t)
	exp, err := otlp.NewHTTPExporter(otlp.ExporterConfig{Endpoint: url})
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	c := NewResultOTLPExportConsumer(bus.NewMemory(), exp, testLogger())

	// A legitimate result: the bus-key tenant and the payload tenant agree.
	good, _ := proto.Marshal(&resultv1.Result{
		TenantId: "tenant-a", AgentId: "a1", CanaryType: "icmp", Success: true, DurationNano: 1234,
	})
	if err := c.handle(context.Background(), bus.Message{Topic: bus.NetworkResultsTopic, Key: []byte("tenant-a"), Value: good}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if c.exportedCount() != 1 {
		t.Fatalf("one handle must flush exactly one export: exported=%d", c.exportedCount())
	}

	select {
	case req := <-received:
		v, ok := probeSuccessValue(req)
		if !ok || v != 1 {
			t.Fatalf("probectl.probe.success = %v (present=%v) at the collector, want 1", v, ok)
		}
		if got := exportedTenant(req); got != "tenant-a" {
			t.Fatalf("exported tenant = %q, want the authoritative bus-key tenant %q", got, "tenant-a")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("probe metrics never reached the collector within a flush")
	}

	// G7-1: a spoofed payload tenant that differs from the authoritative bus-key
	// tenant must NOT export (dropped, never re-attributed to the attacker).
	spoof, _ := proto.Marshal(&resultv1.Result{
		TenantId: "tenant-attacker", AgentId: "a1", CanaryType: "icmp", Success: true,
	})
	if err := c.handle(context.Background(), bus.Message{Topic: bus.NetworkResultsTopic, Key: []byte("tenant-a"), Value: spoof}); err != nil {
		t.Fatalf("handle spoofed: %v", err)
	}
	if c.exportedCount() != 1 {
		t.Fatalf("a spoofed payload tenant must not export: exported=%d, want 1", c.exportedCount())
	}
	if c.droppedCount() != 1 {
		t.Fatalf("a spoofed payload tenant must be dropped: dropped=%d, want 1", c.droppedCount())
	}
	select {
	case <-received:
		t.Fatal("a spoofed payload tenant must never reach the collector (G7-1)")
	case <-time.After(150 * time.Millisecond):
	}
}

// TestResultOTLPExportThroughBus publishes a probe result on the real result bus
// topic, runs the consumer over it, and asserts the collector receives the
// re-exported OTLP metrics — the end-to-end wired path.
func TestResultOTLPExportThroughBus(t *testing.T) {
	url, received := newOTLPMetricsCollector(t)
	exp, err := otlp.NewHTTPExporter(otlp.ExporterConfig{Endpoint: url})
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}

	b := bus.NewMemory()
	c := NewResultOTLPExportConsumer(b, exp, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	if !b.WaitForSubscribers(ctx, bus.NetworkResultsTopic, 1) {
		t.Fatal("consumer never subscribed to the result topic")
	}
	payload, _ := proto.Marshal(&resultv1.Result{
		TenantId: "tenant-b", AgentId: "a2", CanaryType: "tcp", Success: true, DurationNano: 42,
	})
	if err := b.Publish(ctx, bus.NetworkResultsTopic, bus.TenantKey("tenant-b", ""), payload); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case req := <-received:
		if got := exportedTenant(req); got != "tenant-b" {
			t.Fatalf("exported tenant = %q, want tenant-b", got)
		}
		if v, ok := probeSuccessValue(req); !ok || v != 1 {
			t.Fatalf("probectl.probe.success = %v (present=%v), want 1", v, ok)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a result published on the bus never reached the collector")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
}

// TestResultOTLPExportMalformedAndFailure covers the at-least-once + fail-closed
// edges: a malformed payload is dropped without wedging the stream; an export
// failure returns an error (so the record redelivers) and is counted; an unkeyed
// record (no authoritative tenant) is dropped closed, never exported.
func TestResultOTLPExportMalformedAndFailure(t *testing.T) {
	valid, _ := proto.Marshal(&resultv1.Result{TenantId: "tenant-a", Success: true})

	// Malformed payload: dropped (handled), never exported, stream not wedged.
	exp := &fakeExporter{}
	c := NewResultOTLPExportConsumer(bus.NewMemory(), exp, testLogger())
	if err := c.handle(context.Background(), bus.Message{Key: []byte("tenant-a"), Value: []byte("garbage")}); err != nil {
		t.Fatalf("malformed payload must not error the stream: %v", err)
	}
	if exp.calls != 0 {
		t.Fatalf("malformed payload must not export: calls=%d", exp.calls)
	}

	// Export failure: error returned (redelivery) + counted.
	expF := &fakeExporter{fail: true}
	cf := NewResultOTLPExportConsumer(bus.NewMemory(), expF, testLogger())
	if err := cf.handle(context.Background(), bus.Message{Key: []byte("tenant-a"), Value: valid}); err == nil {
		t.Fatal("export failure must return an error so the record redelivers")
	}
	if cf.failedCount() != 1 {
		t.Fatalf("export failure not counted: %d", cf.failedCount())
	}

	// Unkeyed record: no authoritative tenant → dropped closed, never exported.
	expU := &fakeExporter{}
	cu := NewResultOTLPExportConsumer(bus.NewMemory(), expU, testLogger())
	if err := cu.handle(context.Background(), bus.Message{Value: valid}); err != nil {
		t.Fatalf("unkeyed record must be dropped without erroring: %v", err)
	}
	if expU.calls != 0 {
		t.Fatalf("unkeyed record must not export: calls=%d", expU.calls)
	}
	if cu.droppedCount() != 1 {
		t.Fatalf("unkeyed record must be dropped closed: dropped=%d, want 1", cu.droppedCount())
	}
}
