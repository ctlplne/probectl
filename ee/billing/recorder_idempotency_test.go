// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package billing

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/usage"
)

// commitThenErrStore models the AUD-21 hazard the plain MemStore cannot: a
// store that DURABLY APPLIES a batch and THEN returns an error to the client (a
// transaction that committed on the server, whose commit ack the client never
// saw). It dedups on the batch's idempotency key, exactly as the real PGStore
// does through usage_flush_batches — so a retry of a batch it already applied is
// a no-op.
type commitThenErrStore struct {
	mu      sync.Mutex
	applied map[string]bool
	totals  map[counterKey]int64
	calls   int
	failAt  int // 1-based AddCounters call that persists then errors; 0 = never
}

func newCommitThenErrStore(failAt int) *commitThenErrStore {
	return &commitThenErrStore{applied: map[string]bool{}, totals: map[counterKey]int64{}, failAt: failAt}
}

func (s *commitThenErrStore) AddCounters(_ context.Context, deltas []CounterDelta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	id := batchIDOf(deltas)
	if id != "" && s.applied[id] {
		return nil // the batch already landed durably — idempotent no-op
	}
	for _, d := range deltas {
		s.totals[counterKey{tenant: d.TenantID, meter: d.Meter, period: d.Period}] += d.Delta
	}
	if id != "" {
		s.applied[id] = true
	}
	if s.calls == s.failAt {
		return context.DeadlineExceeded // committed, but the client sees an error
	}
	return nil
}

func (s *commitThenErrStore) total(tenant, meter string, period time.Time) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.totals[counterKey{tenant: tenant, meter: meter, period: period}]
}

func (*commitThenErrStore) SetGauge(context.Context, string, string, time.Time, int64) error {
	return nil
}
func (*commitThenErrStore) Query(context.Context, time.Time, time.Time, string) ([]UsageRecord, error) {
	return nil, nil
}
func (*commitThenErrStore) QuotaFor(context.Context, string) (Quota, error) { return Quota{}, nil }
func (*commitThenErrStore) SetQuota(context.Context, Quota) error           { return nil }

// TestFlushNeverDoubleCountsOnCommitThenError is the AUD-21 regression for the
// recorder: a flush whose store COMMITTED the batch but then reported an error
// used to merge the deltas back and re-apply them on the next flush — double-
// counting billing data while docs/metering.md promised "never double-counted".
// The retried batch must keep its idempotency key so the store dedups it; two
// flushes net a SINGLE application.
func TestFlushNeverDoubleCountsOnCommitThenError(t *testing.T) {
	store := newCommitThenErrStore(1) // first AddCounters persists, then errors
	rec := NewRecorder(store, testLog()).withClock(func() time.Time { return t0 })
	ctx := context.Background()

	rec.Record("tnA", usage.MeterResultsIngested, 10)

	// Flush 1: the store durably applies the batch, then the client sees an error.
	if err := rec.Flush(ctx); err == nil {
		t.Fatal("the fault-injected flush must surface the store error")
	}
	// Flush 2: the recorder retries the SAME batch id; the store dedups it.
	if err := rec.Flush(ctx); err != nil {
		t.Fatalf("retry flush: %v", err)
	}

	if got := store.total("tnA", usage.MeterResultsIngested, PeriodStart(t0)); got != 10 {
		t.Fatalf("AUD-21: commit-then-error double-counted: got %d, want 10", got)
	}
	// The retry must really have re-presented the batch (not silently dropped it).
	if store.calls < 2 {
		t.Fatalf("expected the recorder to retry the batch; got %d AddCounters calls", store.calls)
	}
}
