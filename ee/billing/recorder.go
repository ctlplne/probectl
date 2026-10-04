// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package billing

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Recorder is the usage.Recorder implementation: counters buffer in memory
// (bucketed at RECORD time, so hour boundaries are exact) and flush to the
// store on a cadence. Billing-critical losslessness: a failed flush is retried
// on the next tick — counts are never dropped, only delayed. A retried batch
// keeps its stable idempotency key, so a batch the store already durably
// applied (a commit that the client only saw fail) is deduped on retry rather
// than re-applied — never double-counted (AUD-21). Record is O(1) under a mutex
// (the hot ingest paths stay cheap).
type Recorder struct {
	store Store
	log   *slog.Logger
	now   func() time.Time
	newID func() string // batch-id minter; overridable in tests

	mu      sync.Mutex
	pending map[counterKey]int64
	// retry holds batches a prior flush could not confirm, newest appended at
	// the far end. Each batch keeps its stable BatchID so the store can dedup a
	// batch it already applied. New activity accumulates in pending SEPARATELY,
	// so a retry never drags fresh deltas under an already-applied id.
	retry [][]CounterDelta
}

type counterKey struct {
	tenant, meter string
	period        time.Time
}

// NewRecorder builds the buffered recorder.
func NewRecorder(store Store, log *slog.Logger) *Recorder {
	if log == nil {
		log = slog.Default()
	}
	return &Recorder{store: store, log: log, now: time.Now, newID: uuid.NewString, pending: map[counterKey]int64{}}
}

// withClock overrides time (tests).
func (r *Recorder) withClock(now func() time.Time) *Recorder {
	r.now = now
	return r
}

// Record implements usage.Recorder.
func (r *Recorder) Record(tenantID, meter string, delta int64) {
	if tenantID == "" || delta <= 0 {
		return
	}
	k := counterKey{tenant: tenantID, meter: meter, period: PeriodStart(r.now())}
	r.mu.Lock()
	r.pending[k] += delta
	r.mu.Unlock()
}

// Flush writes the buffered deltas. It drains any unconfirmed batches first
// (oldest to newest, each under its own stable idempotency key) and then the
// newly accumulated deltas as one fresh batch. On the first store error it
// re-queues the failed batch and everything after it — unchanged, same ids —
// for the next tick: counts are delayed, never lost, and a batch the store
// already applied is deduped on retry, never doubled (AUD-21).
func (r *Recorder) Flush(ctx context.Context) error {
	r.mu.Lock()
	batches := r.retry
	r.retry = nil
	if len(r.pending) > 0 {
		id := r.newID()
		deltas := make([]CounterDelta, 0, len(r.pending))
		for k, v := range r.pending {
			deltas = append(deltas, CounterDelta{TenantID: k.tenant, Meter: k.meter, Period: k.period, Delta: v, BatchID: id})
		}
		r.pending = map[counterKey]int64{}
		batches = append(batches, deltas)
	}
	r.mu.Unlock()

	if len(batches) == 0 {
		return nil
	}

	for i, b := range batches {
		if err := r.store.AddCounters(ctx, b); err != nil {
			// Re-queue the failed batch and everything after it, preserving
			// order and each batch's stable id so the retry dedups a batch the
			// store already durably applied (AUD-21: never double-count).
			r.mu.Lock()
			r.retry = append(append([][]CounterDelta(nil), batches[i:]...), r.retry...)
			r.mu.Unlock()
			return err
		}
	}
	return nil
}

// Run flushes on the interval until ctx ends, with one final flush on the
// way out (best-effort drain of the buffer at shutdown).
func (r *Recorder) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := r.Flush(flushCtx); err != nil {
				r.log.Warn("metering: final flush failed (deltas retained in memory are lost at exit)", "error", err.Error())
			}
			cancel()
			return
		case <-t.C:
			if err := r.Flush(ctx); err != nil {
				r.log.Warn("metering: flush failed; deltas retained for retry", "error", err.Error())
			}
		}
	}
}
