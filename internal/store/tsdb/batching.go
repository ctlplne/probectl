// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tsdb

import (
	"context"
	"errors"
	"sync"
	"time"
)

var errBatchingWriterClosed = errors.New("tsdb: batching writer is closed")

const tsdbBackgroundFlushTimeout = 5 * time.Second

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
	closed  bool

	flushMu  sync.Mutex
	closeErr error
}

type flushResult struct {
	done chan struct{}
	err  error
	// fenced maps a tenant_id rejected by the write fence THIS flush to its
	// fence error. It is keyed per tenant so a coalesced batch fails only the
	// fenced tenants' callers, never their co-batched neighbours (G7-1).
	fenced map[string]error
}

// resultFor returns the error a caller whose contributed series are chunk must
// surface for this flush. When any of the caller's OWN tenants was fenced this
// flush it returns that tenant's fence error (which names only that tenant, so
// a co-batched tenant's id/status never leaks to a different caller); otherwise
// it returns the shared eligible-write result (nil on success).
func (r *flushResult) resultFor(chunk []Series) error {
	if len(r.fenced) > 0 {
		for i := range chunk {
			if ferr, ok := r.fenced[chunk[i].Labels[TenantLabel]]; ok {
				return ferr
			}
		}
	}
	return r.err
}

// partitionedWriter is the optional seam the tenant write fence implements so a
// coalesced MULTI-TENANT batch is fenced PER TENANT: eligible tenants' series
// are stored and only the fenced tenants' series are rejected, so one tenant's
// lifecycle state never fails another tenant's write (docs/guardrails.md G7-1).
// fenced maps each rejected tenant_id to its fence error; every other tenant's
// series is written and err reports only a batch-wide failure.
type partitionedWriter interface {
	WritePartitioned(ctx context.Context, series []Series) (fenced map[string]error, err error)
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
	if err := ValidateTenantSeries(series); err != nil {
		return err
	}
	for len(series) > 0 {
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			return errBatchingWriterClosed
		}
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
		chunk := series[:n]
		b.pending = append(b.pending, chunk...)
		series = series[n:]
		full := len(b.pending) >= b.maxSeries
		b.mu.Unlock()

		if full {
			b.flush() // size trigger: flush now rather than wait for the timer
		}
		if done, cancelErr := waitFlush(ctx, batch); !done {
			return cancelErr
		}
		// Per-tenant fence attribution (G7-1): this caller fails ONLY when one of
		// its OWN series' tenants was fenced this flush; a co-batched tenant's
		// fence never fails this caller, and the error names only this caller's
		// own tenant.
		if err := batch.resultFor(chunk); err != nil {
			return err
		}
	}
	return nil
}

// WriteGlobal forwards explicit non-tenant control-plane metrics to an
// underlying GlobalWriter. These low-volume series do not need batching, and
// bypassing the tenant-owned queue keeps the escape hatch visible.
func (b *BatchingWriter) WriteGlobal(ctx context.Context, series []Series) error {
	if len(series) == 0 {
		return nil
	}
	if err := ValidateGlobalSeries(series); err != nil {
		return err
	}
	b.flushMu.Lock()
	defer b.flushMu.Unlock()
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return errBatchingWriterClosed
	}
	gw, ok := b.w.(GlobalWriter)
	if !ok {
		return ErrGlobalWriterUnsupported
	}
	return gw.WriteGlobal(ctx, series)
}

// batchCancelGrace is how long Write waits for an in-flight shared batch to
// report its real result after the caller's context is canceled, before
// surfacing the cancellation (CORRECT-011). Small: the flush is already running.
const batchCancelGrace = 250 * time.Millisecond

// waitFlush blocks until this caller's batch has flushed (done=true) or the
// caller's context is canceled with no result yet (done=false, cancelErr set).
// The caller reads its per-tenant outcome from the batch only when done is true.
func waitFlush(ctx context.Context, batch *flushResult) (done bool, cancelErr error) {
	select {
	case <-batch.done:
		return true, nil
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
			return true, nil
		case <-time.After(batchCancelGrace):
			return false, ctx.Err()
		}
	}
}

// flush writes the current pending batch and releases everyone waiting on it.
// Safe to call from the timer and from a size-triggered Write; it swaps the
// open batch out under the lock so exactly one flush handles each batch.
func (b *BatchingWriter) flush() {
	b.flushMu.Lock()
	defer b.flushMu.Unlock()
	b.flushLocked()
}

// flushLocked writes the current queue while flushMu is held. This makes the
// real backend mutation part of the writer lifecycle: Close cannot overtake a
// timer flush after it has removed the batch from the queue.
func (b *BatchingWriter) flushLocked() {
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
	// A batch is shared by several callers, so no individual caller may cancel
	// the real mutation. It still needs an internally-owned deadline: otherwise
	// a stalled backend pins flushMu and prevents Close from completing.
	ctx, cancel := context.WithTimeout(context.Background(), tsdbBackgroundFlushTimeout)
	if pw, ok := b.w.(partitionedWriter); ok {
		// Per-tenant fence (G7-1): store every eligible tenant's series and
		// reject ONLY the fenced tenants', so one offboarding tenant's lifecycle
		// state cannot fail every co-batched tenant that shares this batch.
		batch.fenced, batch.err = pw.WritePartitioned(ctx, pending)
	} else {
		batch.err = b.w.Write(ctx, pending)
	}
	cancel()
	close(batch.done) // wake every Write that joined this batch with the shared result
}

// Close flushes any open batch and closes the underlying writer.
func (b *BatchingWriter) Close() error {
	b.flushMu.Lock()
	defer b.flushMu.Unlock()

	b.mu.Lock()
	if b.closed {
		err := b.closeErr
		b.mu.Unlock()
		return err
	}
	b.closed = true
	b.mu.Unlock()

	b.flushLocked()
	err := b.w.Close()
	b.mu.Lock()
	b.closeErr = err
	b.mu.Unlock()
	return err
}
