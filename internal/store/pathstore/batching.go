// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pathstore

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ctlplne/probectl/internal/path"
)

const pathBackgroundFlushTimeout = 5 * time.Second

var errBatchingSaverClosed = errors.New("pathstore: batching saver is closed")

// BatchingSaver adds a CROSS-PATH batching window over a Store (Sprint 14,
// SCALE-009): hops/links were already batched per path (one JSONEachRow body
// each), but every discovery still cost its own pair of INSERT requests.
// Saves now enqueue (write-behind) and a flusher combines every path saved
// inside the window into ONE insert per table.
//
// Semantics, stated:
//   - Save returns immediately; persistence lags by ≤ the window. Flush
//     errors are LOUD (log + lost counter) — a path snapshot is
//     re-discoverable, so the trade is bounded loss-on-crash vs per-path
//     round-trips (the SCALE-009 ask).
//   - Latest FLUSHES pending saves first — read-your-write holds for the
//     discover→view flow.
//   - Close flushes.
type BatchingSaver struct {
	inner  Store
	log    *slog.Logger
	window time.Duration
	max    int

	mu      sync.Mutex
	pending []pendingPath
	timer   *time.Timer
	closed  bool

	flushMu  sync.Mutex
	closeErr error

	flushes atomic.Uint64
	saved   atomic.Uint64
	lost    atomic.Uint64
}

type pendingPath struct {
	tenantID string
	p        *path.Path
}

// batchSaver is the optional fast path a backend can implement (the
// ClickHouse store does): all paths in one insert per table.
type batchSaver interface {
	SaveBatch(ctx context.Context, items []PathItem) error
}

// partitionedBatchSaver is the optional seam the tenant write fence implements
// so a coalesced MULTI-TENANT flush is fenced PER TENANT: eligible tenants'
// paths are persisted and only the fenced tenants' paths are dropped, so one
// tenant's lifecycle state never fails another tenant's write
// (docs/guardrails.md G7-1). fenced maps each dropped tenant_id to its fence
// error; err reports only a batch-wide failure.
type partitionedBatchSaver interface {
	SaveBatchPartitioned(ctx context.Context, items []PathItem) (fenced map[string]error, err error)
}

// PathItem is one queued discovery.
type PathItem struct {
	TenantID string
	P        *path.Path
}

// NewBatchingSaver wraps inner with the window (default 100ms) and max batch
// size (default 32).
func NewBatchingSaver(inner Store, log *slog.Logger, window time.Duration, maxBatch int) *BatchingSaver {
	if log == nil {
		log = slog.Default()
	}
	if window <= 0 {
		window = 100 * time.Millisecond
	}
	if maxBatch <= 0 {
		maxBatch = 32
	}
	return &BatchingSaver{inner: inner, log: log, window: window, max: maxBatch}
}

// Save enqueues and returns; the window flusher persists.
func (b *BatchingSaver) Save(_ context.Context, tenantID string, p *path.Path) error {
	if tenantID == "" {
		return ErrNoTenant
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return errBatchingSaverClosed
	}
	b.pending = append(b.pending, pendingPath{tenantID: tenantID, p: p})
	full := len(b.pending) >= b.max
	if b.timer == nil && !full {
		b.timer = time.AfterFunc(b.window, b.flushBackground)
	}
	b.mu.Unlock()
	if full {
		b.flushBackground()
	}
	return nil
}

// flushBackground bounds internally-owned timer, size-trigger, and shutdown
// work. In production the inner store first acquires the durable tenant writer
// lease; an unavailable database or erasure lock must fail closed without
// pinning a flusher forever.
func (b *BatchingSaver) flushBackground() {
	ctx, cancel := context.WithTimeout(context.Background(), pathBackgroundFlushTimeout)
	defer cancel()
	b.Flush(ctx)
}

// flushForRead drains the pending batch ahead of a read-your-write read. The
// flush runs under an INTERNALLY-OWNED context derived from the caller's —
// cancellation stripped (context.WithoutCancel) and re-bounded exactly like
// flushBackground — NOT the caller's cancelable context. Flush drains the
// DEPLOYMENT-WIDE, cross-tenant batch, so the reader's own request
// cancellation (client disconnect / timeout) must never abort the shared flush:
// doing so counts every co-batched tenant's queued paths lost and drops them,
// letting ONE tenant's canceled read destroy ANOTHER tenant's writes — a
// tenant-isolation break (docs/guardrails.md G7-1), so it fails closed instead.
// The caller's values survive for tracing; the bound still fails closed on an
// unavailable store. The delegated read itself keeps the caller's context.
func (b *BatchingSaver) flushForRead(ctx context.Context) {
	flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pathBackgroundFlushTimeout)
	defer cancel()
	b.Flush(flushCtx)
}

// Flush persists everything pending (one combined insert per table when the
// backend supports it). Safe to call concurrently.
func (b *BatchingSaver) Flush(ctx context.Context) {
	b.flushMu.Lock()
	defer b.flushMu.Unlock()
	b.flush(ctx)
}

// flush persists the current queue while flushMu is held. Serializing the
// backend mutation makes its lifetime visible to Close: shutdown cannot close
// the backend while a timer or caller is still using it.
func (b *BatchingSaver) flush(ctx context.Context) {
	b.mu.Lock()
	batch := b.pending
	b.pending = nil
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	b.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	b.flushes.Add(1)

	// Per-tenant fence (G7-1): when the fence can render a per-tenant verdict,
	// store every eligible tenant's paths and drop ONLY the fenced tenants' —
	// one offboarding tenant's lifecycle state must not drop every co-batched
	// tenant's paths from the shared flush.
	if pbs, ok := b.inner.(partitionedBatchSaver); ok {
		items := make([]PathItem, len(batch))
		for i, q := range batch {
			items[i] = PathItem{TenantID: q.tenantID, P: q.p}
		}
		fenced, err := pbs.SaveBatchPartitioned(ctx, items)
		if err != nil {
			b.lost.Add(uint64(len(batch)))
			b.log.Error("PATH BATCH LOST: combined insert failed (paths are re-discoverable; investigate the store)",
				"paths", len(batch), "error", err.Error())
			return
		}
		if len(fenced) == 0 {
			b.saved.Add(uint64(len(batch)))
			return
		}
		dropped := 0
		for i := range items {
			if _, bad := fenced[items[i].TenantID]; bad {
				dropped++
			}
		}
		stored := len(batch) - dropped
		b.saved.Add(uint64(stored))
		// A fenced tenant's dropped paths are a deliberate lifecycle rejection,
		// not an unexpected store failure, but they are still paths not persisted
		// — counted (lostCount) and logged so the drop stays observable.
		b.lost.Add(uint64(dropped))
		b.log.Warn("PATH BATCH PARTIAL: dropped offboarding/absent tenants' paths and stored the rest (G7-1: one tenant's lifecycle must not drop another's)",
			"dropped", dropped, "stored", stored)
		return
	}

	if bs, ok := b.inner.(batchSaver); ok {
		items := make([]PathItem, len(batch))
		for i, q := range batch {
			items[i] = PathItem{TenantID: q.tenantID, P: q.p}
		}
		if err := bs.SaveBatch(ctx, items); err != nil {
			b.lost.Add(uint64(len(batch)))
			b.log.Error("PATH BATCH LOST: combined insert failed (paths are re-discoverable; investigate the store)",
				"paths", len(batch), "error", err.Error())
			return
		}
		b.saved.Add(uint64(len(batch)))
		return
	}
	for _, q := range batch {
		if err := b.inner.Save(ctx, q.tenantID, q.p); err != nil {
			b.lost.Add(1)
			b.log.Error("PATH SAVE LOST", "tenant", q.tenantID, "error", err.Error())
			continue
		}
		b.saved.Add(1)
	}
}

// Latest flushes pending saves first (read-your-write), then delegates. The
// flush uses flushForRead so this reader's cancellation cannot drop another
// tenant's queued writes from the shared batch (G7-1).
func (b *BatchingSaver) Latest(ctx context.Context, tenantID, target string) (*path.Path, bool, error) {
	b.flushForRead(ctx)
	return b.inner.Latest(ctx, tenantID, target)
}

// History flushes pending saves first so a just-discovered round is immediately
// available to the scrubber and stable-share flow. Like Latest it flushes via
// flushForRead so a canceled history read never drops the shared batch (G7-1).
func (b *BatchingSaver) History(ctx context.Context, tenantID, target string, q HistoryQuery) ([]Snapshot, error) {
	b.flushForRead(ctx)
	return b.inner.History(ctx, tenantID, target, q)
}

// Close flushes and closes the backend.
func (b *BatchingSaver) Close() error {
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

	ctx, cancel := context.WithTimeout(context.Background(), pathBackgroundFlushTimeout)
	b.flush(ctx)
	cancel()
	err := b.inner.Close()
	b.mu.Lock()
	b.closeErr = err
	b.mu.Unlock()
	return err
}

// lost reports paths dropped by failed flushes (should be 0).
func (b *BatchingSaver) lostCount() uint64 { return b.lost.Load() }
