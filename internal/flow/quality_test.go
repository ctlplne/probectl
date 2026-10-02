// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
)

type qualityCaptureEmitter struct {
	receipts []QualityReceipt
	err      error
}

func (*qualityCaptureEmitter) Emit(context.Context, []Record) error { return nil }

func (e *qualityCaptureEmitter) EmitQuality(_ context.Context, receipts []QualityReceipt) error {
	e.receipts = append(e.receipts, receipts...)
	return e.err
}

func validQualityReceipt() QualityReceipt {
	end := time.Date(2026, 7, 27, 20, 0, 0, 0, time.UTC)
	last := end.Add(-time.Second)
	return QualityReceipt{
		TenantID: "tenant-a", AgentID: "flow-agent-1",
		ExporterAddress: "192.0.2.10", Protocol: ProtoIPFIX,
		WindowStartedAt: end.Add(-time.Minute), WindowEndedAt: end,
		LastPacketAt: last, LastValidRecordAt: &last,
		PacketsReceived: 10, RecordsDecoded: 30,
		TemplateState: QualityTemplateReady, SamplingState: QualitySamplingSampled,
		State: QualityStateHealthy, Reason: QualityReasonReceivingValidRecords,
		NextAction: QualityActionContinueMonitoring,
	}
}

func TestQualityReceiptStateMatrixIsBoundedAndFreeFormTextIsRejected(t *testing.T) {
	base := validQualityReceipt()
	if _, err := ValidateQualityReceipt(base); err != nil {
		t.Fatalf("valid receipt: %v", err)
	}
	stale := EvaluateQualityState(base, base.LastPacketAt.Add(QualityStaleAfter+time.Second))
	stale.WindowEndedAt = base.LastPacketAt.Add(QualityStaleAfter + time.Second)
	if valid, err := ValidateQualityReceipt(stale); err != nil ||
		valid.State != QualityStateStale ||
		valid.NextAction != QualityActionVerifyExporter {
		t.Fatalf("stale receipt=%+v err=%v", valid, err)
	}
	degraded := base
	degraded.QueueDroppedRecords = 2
	degraded = EvaluateQualityState(degraded, degraded.WindowEndedAt)
	if valid, err := ValidateQualityReceipt(degraded); err != nil ||
		valid.Reason != QualityReasonQueueLoss ||
		valid.NextAction != QualityActionReducePressure {
		t.Fatalf("degraded receipt=%+v err=%v", valid, err)
	}
	for name, mutate := range map[string]func(*QualityReceipt){
		"free-form reason":  func(r *QualityReceipt) { r.Reason = "decoder said secret=community" },
		"hostname exporter": func(r *QualityReceipt) { r.ExporterAddress = "router.internal" },
		"unbounded agent":   func(r *QualityReceipt) { r.AgentID = strings.Repeat("a", 129) },
		"counter overflow":  func(r *QualityReceipt) { r.PacketsReceived = MaxQualityCounter + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := base
			mutate(&bad)
			if _, err := ValidateQualityReceipt(bad); err == nil {
				t.Fatalf("invalid receipt accepted: %+v", bad)
			}
		})
	}
}

func TestMemoryQualityStoreIsTenantScopedMonotonicAndDerivesStaleState(t *testing.T) {
	store := NewMemoryQualityStore()
	a := validQualityReceipt()
	b := validQualityReceipt()
	b.TenantID, b.AgentID, b.ExporterAddress = "tenant-b", "flow-agent-b", "198.51.100.20"
	if err := store.UpsertQualityReceipt(context.Background(), "tenant-a", a); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertQualityReceipt(context.Background(), "tenant-b", b); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertQualityReceipt(context.Background(), "tenant-a", b); err == nil {
		t.Fatal("cross-tenant receipt write was accepted")
	}
	older := a
	older.WindowEndedAt = a.WindowEndedAt.Add(-time.Minute)
	older.WindowStartedAt = older.WindowEndedAt.Add(-time.Minute)
	older.LastPacketAt = older.WindowEndedAt
	older.LastValidRecordAt = &older.LastPacketAt
	older = EvaluateQualityState(older, older.WindowEndedAt)
	if err := store.UpsertQualityReceipt(context.Background(), "tenant-a", older); err != nil {
		t.Fatal(err)
	}
	// Pin the read clock to the fixture window: the store prunes receipts
	// older than QualityReceiptRetention relative to the as-of time, and the
	// fixture's fixed timestamps must not turn this into a time bomb (DPR-004).
	rows, truncated, err := store.ListQualityReceipts(context.Background(), "tenant-a", QualityFilter{AsOf: a.WindowEndedAt})
	if err != nil || truncated || len(rows) != 1 {
		t.Fatalf("tenant-a rows=%+v truncated=%v err=%v", rows, truncated, err)
	}
	// And prove the retention pruning itself: read as of a day past the
	// window and the receipt is retained; a day past retention and it is gone.
	if kept, _, err := store.ListQualityReceipts(context.Background(), "tenant-a", QualityFilter{AsOf: a.WindowEndedAt.Add(24 * time.Hour)}); err != nil || len(kept) != 1 {
		t.Fatalf("receipt inside retention rows=%+v err=%v", kept, err)
	}
	if gone, _, err := store.ListQualityReceipts(context.Background(), "tenant-a", QualityFilter{AsOf: a.WindowEndedAt.Add(QualityReceiptRetention + 24*time.Hour)}); err != nil || len(gone) != 0 {
		t.Fatalf("receipt past retention rows=%+v err=%v", gone, err)
	}
	if rows[0].ExporterAddress == b.ExporterAddress || rows[0].WindowEndedAt != a.WindowEndedAt {
		t.Fatalf("cross-tenant or stale overwrite: %+v", rows[0])
	}
	for name, filter := range map[string]QualityFilter{
		"unbounded agent": {AgentID: strings.Repeat("a", 129)},
		"hostname":        {Exporter: "router.internal"},
		"protocol":        {Protocol: "invented-flow"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := store.ListQualityReceipts(context.Background(), "tenant-a", filter); err == nil {
				t.Fatalf("invalid filter accepted: %+v", filter)
			}
		})
	}
}

func TestMemoryQualityStoreUsesFilterAsOfAtStaleBoundary(t *testing.T) {
	store := NewMemoryQualityStore()
	asOf := time.Date(2026, 7, 28, 2, 0, 0, 0, time.UTC)
	receipt := validQualityReceipt()
	receipt.WindowStartedAt = asOf.Add(-time.Minute)
	receipt.WindowEndedAt = asOf
	receipt.LastPacketAt = asOf.Add(-QualityStaleAfter)
	receipt.LastValidRecordAt = &receipt.LastPacketAt
	receipt = EvaluateQualityState(receipt, asOf)
	if err := store.UpsertQualityReceipt(context.Background(), receipt.TenantID, receipt); err != nil {
		t.Fatal(err)
	}

	healthy, _, err := store.ListQualityReceipts(context.Background(), receipt.TenantID, QualityFilter{
		State: QualityStateHealthy, AsOf: asOf,
	})
	if err != nil || len(healthy) != 1 || healthy[0].State != QualityStateHealthy {
		t.Fatalf("healthy boundary rows=%+v err=%v", healthy, err)
	}
	staleAsOf := asOf.Add(time.Nanosecond)
	stale, _, err := store.ListQualityReceipts(context.Background(), receipt.TenantID, QualityFilter{
		State: QualityStateStale, AsOf: staleAsOf,
	})
	if err != nil || len(stale) != 1 || stale[0].State != QualityStateStale {
		t.Fatalf("stale boundary rows=%+v err=%v", stale, err)
	}
}

func TestCollectorQualitySetIsBoundedAndCountersSaturate(t *testing.T) {
	c, err := New(testConfig(), &captureEmitter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < MaxQualityReceiptsPerAgent+10; i++ {
		exporter := fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
		c.observeQualityPacket(exporter, ProtoNetFlow5, now.Add(time.Duration(i)*time.Nanosecond),
			[]Record{{SamplingRate: 1}}, 0, false)
	}
	if got := len(c.qualitySnapshot(now.Add(time.Minute))); got > MaxQualityReceiptsPerAgent {
		t.Fatalf("quality cardinality=%d, max=%d", got, MaxQualityReceiptsPerAgent)
	}
	if got := saturatingQualityAdd(MaxQualityCounter-1, 10); got != MaxQualityCounter {
		t.Fatalf("saturating counter=%d", got)
	}
}

// TestMalformedQualityWindowNeverWedgesSubsequentReceiptEmission is the RTP-12
// regression: untrusted flow ingest must never be able to wedge quality
// reporting. One malformed/unrepresentable window must not fail the whole
// receipt batch forever and strand healthy exporters as "stale".
//
// The malformed window here models the exact mechanism in the finding: a
// hostile/corrupt sFlow datagram is accounted as a template miss, but sFlow has
// no templates, so quality_collector.go marks the window template_missing and
// the receipt can never validate (quality.go: "protocol has no templates").
// The real bus emitter validates every receipt and rejects a batch containing
// any invalid one — so before the fix that single bad window blocked the batch
// on every tick and the healthy IPFIX exporter's receipt was never emitted.
// This test drives the real collector + real BusEmitter (over a capture bus).
func TestMalformedQualityWindowNeverWedgesSubsequentReceiptEmission(t *testing.T) {
	cb := &captureBus{}
	c, err := New(testConfig(), NewBusEmitter(cb, "t-acme"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 28, 1, 0, 0, 0, time.UTC)

	// A malformed sFlow datagram mis-recorded as a template miss on a protocol
	// that has no templates -> a window whose receipt can never validate.
	c.observeQualityPacket("198.51.100.1", ProtoSFlow5, now, nil, 1, true)
	// A healthy IPFIX exporter in the same agent/batch.
	c.observeQualityPacket("192.0.2.10", ProtoIPFIX, now, []Record{{SamplingRate: 100}}, 0, false)

	c.emitQualityReceipts(context.Background(), now.Add(time.Minute))

	if cb.n == 0 {
		t.Fatalf("one malformed window wedged the whole batch: the healthy exporter's receipt never emitted (publishes=%d)", cb.n)
	}
	var batch flowv1.FlowIngestQualityBatch
	if err := proto.Unmarshal(cb.value, &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.GetReceipts()) != 1 || batch.GetReceipts()[0].GetExporterAddress() != "192.0.2.10" {
		t.Fatalf("expected only the healthy exporter to emit, got %+v", batch.GetReceipts())
	}
	// The bad window is dropped and accounted, not silently swallowed, and a
	// dropped window must not count as an emit failure.
	if s := c.StatsSnapshot(); s.QualityInvalidReceipts != 1 || s.QualityReceipts != 1 || s.QualityEmitErrors != 0 {
		t.Fatalf("quality stats=%+v (want 1 invalid, 1 emitted, 0 emit errors)", s)
	}

	// And the pipeline stays unwedged: a fresh healthy window on the next tick
	// still emits even though the malformed window is still present.
	cb.n = 0
	c.observeQualityPacket("192.0.2.10", ProtoIPFIX, now.Add(time.Minute), []Record{{SamplingRate: 100}}, 0, false)
	c.emitQualityReceipts(context.Background(), now.Add(2*time.Minute))
	if cb.n == 0 {
		t.Fatalf("subsequent window wedged: healthy exporter stopped emitting after a malformed window")
	}
}

func TestCollectorEmitsQualityWindowAndRestoresItOnFailure(t *testing.T) {
	now := time.Date(2026, 7, 28, 1, 0, 0, 0, time.UTC)
	success := &qualityCaptureEmitter{}
	c, err := New(testConfig(), success, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.observeQualityPacket("192.0.2.44", ProtoIPFIX, now,
		[]Record{{SamplingRate: 100}}, 0, false)
	c.emitQualityReceipts(context.Background(), now.Add(time.Minute))
	if len(success.receipts) != 1 ||
		success.receipts[0].PacketsReceived != 1 ||
		success.receipts[0].RecordsDecoded != 1 ||
		success.receipts[0].State != QualityStateHealthy {
		t.Fatalf("emitted quality receipt=%+v", success.receipts)
	}
	if stats := c.StatsSnapshot(); stats.QualityReceipts != 1 || stats.QualityEmitErrors != 0 {
		t.Fatalf("successful quality stats=%+v", stats)
	}

	failing := &qualityCaptureEmitter{err: errors.New("local bus unavailable")}
	c, err = New(testConfig(), failing, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.observeQualityPacket("198.51.100.55", ProtoNetFlow5, now,
		[]Record{{SamplingRate: 1}}, 0, false)
	c.emitQualityReceipts(context.Background(), now.Add(time.Minute))
	restored := c.qualitySnapshot(now.Add(time.Minute))
	if len(restored) != 1 || restored[0].PacketsReceived != 1 || restored[0].RecordsDecoded != 1 {
		t.Fatalf("failed quality window was not restored: %+v", restored)
	}
	if stats := c.StatsSnapshot(); stats.QualityReceipts != 0 || stats.QualityEmitErrors != 1 {
		t.Fatalf("failed quality stats=%+v", stats)
	}
}
