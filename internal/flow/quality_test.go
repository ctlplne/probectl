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
	"strings"
	"testing"
	"time"
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
