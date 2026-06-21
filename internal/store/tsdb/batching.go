// SPDX-License-Identifier: LicenseRef-probectl-TBD

package tsdb

import (
	"context"
	"sync"
	"time"
)

// BatchingWriter coalesces concurrent Write calls into one underlying
// remote-write request (SCALE-001). The ingest hot path did one Prometheus
// remote-write HTTP POST PER probe result; under a fleet that is a POST per
// message. This wrapper merges the series from all Writes that arrive within a
// small window (or until a series cap) into a single WriteRequest — far fewer,
// larger POSTs — while preserving PER-CALLER error attribution: every Write
// blocks until its batch flushes and returns THAT batch's result, so the result
// pipeline still dead-letters exactly the messages whose write failed
// (per-message DLQ attribution intact). With one writer goroutine it just adds
// up to maxWait latency; the win shows when the bus workers write concurrently.
type BatchingWriter struct {
	w         Writer
	maxSeries int
	maxWait   time.Duration

	mu      sync.Mutex
	pending []Series
	batch   *flushResult // the open batch every current caller will share
	timer   *time.Timer
}

type flushResult struct {
	done chan struct{}
	err  error
}

// NewBatchingWriter wraps w. maxSeries (<=0 => 500) and maxWait (<=0 => 50ms)
// bound each coalesced WriteRequest, matching the SCALE-001 envelope.
func NewBatchingWriter(w Writer, maxSeries int, maxWait time.Duration) *BatchingWriter {
	if maxSeries <= 0 {
		maxSeries = 500
	}
	if maxWait <= 0 {
		maxWait = 50 * time.Millisecond
	}
	return &BatchingWriter{w: w, maxSeries: maxSeries, maxWait: maxWait}
}

// Write adds series to bounded batches and blocks until every chunk containing
// this caller's series is flushed. A single large caller slice is split before
// it can overfill the open batch, so maxSeries is a hard underlying write cap,
// not just a flush trigger. An empty write is a no-op.
func (b *BatchingWriter) Write(ctx context.Context, series []Series) error {
	if len(series) == 0 {
		return nil
	}
	for len(series) > 0 {
		b.mu.Lock()
		if b.batch == nil {
			b.batch = &flushResult{done: make(chan struct{})}
			b.timer = time.AfterFunc(b.maxWait, b.flush)
		}
		room := b.maxSeries - len(b.pending)
		if room <= 0 {
			// Another caller filled the batch between its unlock and flush().
			// This caller has not joined it, so flush and retry against the new
			// batch instead of overfilling the old one.
			b.mu.Unlock()
			b.flush()
			continue
		}
		n := min(len(series), room)
		batch := b.batch
		b.pending = append(b.pending, series[:n]...)
		series = series[n:]
		full := len(b.pending) >= b.maxSeries
		b.mu.Unlock()

		if full {
			b.flush() // size trigger: flush now rather than wait for the timer
		}
		if err := waitFlush(ctx, batch); err != nil {
			return err
		}
	}
	return nil
}

// batchCancelGrace is how long Write waits for an in-flight shared batch to
// report its real result after the caller's context is canceled, before
// surfacing the cancellation (CORRECT-011). Small: the flush is already running.
const batchCancelGrace = 250 * time.Millisecond

func waitFlush(ctx context.Context, batch *flushResult) error {
	select {
	case <-batch.done:
		return batch.err
	case <-ctx.Done():
		// CORRECT-011: the caller's context fired while this batch is in flight.
		// flush() runs under its OWN background context (one caller's cancel must
		// not abort a write shared by other callers), so the write may ALREADY
		// have landed — returning a bare ctx.Err() here told the result pipeline
		// the write FAILED while the row actually stored, which then dead-lettered
		// a duplicate. Give the in-flight batch a brief grace to report its REAL
		// outcome before surfacing the cancel, so the common race resolves to the
		// truth; only a genuinely-still-pending write returns ctx.Err() (which the
		// pipeline now treats as "unknown" and does NOT dead-letter).
		select {
		case <-batch.done:
			return batch.err
		case <-time.After(batchCancelGrace):
			return ctx.Err()
		}
	}
}

// flush writes the current pending batch and releases everyone waiting on it.
// Safe to call from the timer and from a size-triggered Write; it swaps the
// open batch out under the lock so exactly one flush handles each batch.
func (b *BatchingWriter) flush() {
	b.mu.Lock()
	if b.batch == nil {
		b.mu.Unlock()
		return
	}
	pending, batch, timer := b.pending, b.batch, b.timer
	b.pending, b.batch, b.timer = nil, nil, nil
	b.mu.Unlock()

	if timer != nil {
		timer.Stop()
	}
	batch.err = b.w.Write(context.Background(), pending)
	close(batch.done) // wake every Write that joined this batch with the shared result
}

// Close flushes any open batch and closes the underlying writer.
func (b *BatchingWriter) Close() error {
	b.flush()
	return b.w.Close()
}
