// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package billing

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Recorder is the usage.Recorder implementation: counters buffer in memory
// (bucketed at RECORD time, so hour boundaries are exact) and flush to the
// store on a cadence. Billing-critical losslessness: a failed flush merges
// the deltas back and retries next tick — counts are never dropped, only
// delayed. Record is O(1) under a mutex (the hot ingest paths stay cheap).
type Recorder struct {
	store Store
	log   *slog.Logger
	now   func() time.Time

	mu      sync.Mutex
	pending map[counterKey]int64
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
	return &Recorder{store: store, log: log, now: time.Now, pending: map[counterKey]int64{}}
}

// WithClock overrides time (tests).
func (r *Recorder) WithClock(now func() time.Time) *Recorder {
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

// Flush writes the buffered deltas. On error every delta merges back into
// the buffer (lossless) and the error is returned for the caller to log.
func (r *Recorder) Flush(ctx context.Context) error {
	r.mu.Lock()
	if len(r.pending) == 0 {
		r.mu.Unlock()
		return nil
	}
	batch := r.pending
	r.pending = map[counterKey]int64{}
	r.mu.Unlock()

	deltas := make([]CounterDelta, 0, len(batch))
	for k, v := range batch {
		deltas = append(deltas, CounterDelta{TenantID: k.tenant, Meter: k.meter, Period: k.period, Delta: v})
	}
	if err := r.store.AddCounters(ctx, deltas); err != nil {
		r.mu.Lock()
		for k, v := range batch {
			r.pending[k] += v // merge back: delayed, never lost
		}
		r.mu.Unlock()
		return err
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
