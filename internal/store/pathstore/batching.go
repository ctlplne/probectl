package pathstore

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/path"
)

// BatchingSaver adds a CROSS-PATH batching window over a Store (Sprint 14,
// SCALE-009): hops/links were already batched per path (one JSONEachRow body
// each), but every discovery still cost its own pair of INSERT requests.
// Saves now enqueue (write-behind) and a flusher combines every path saved
// inside the window into ONE insert per table.
//
// Semantics, stated:
//   - Save returns immediately; persistence lags by ≤ the window. Flush
//     errors are LOUD (log + Lost counter) — a path snapshot is
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

// PathItem is one queued discovery.
type PathItem struct {
	TenantID string
	P        *path.Path
}

// NewBatchingSaver wraps inner with the window (default 100ms) and max batch
// size (default 32).
func NewBatchingSaver(inner Store, log *slog.Logger, window time.Duration, max int) *BatchingSaver {
	if log == nil {
		log = slog.Default()
	}
	if window <= 0 {
		window = 100 * time.Millisecond
	}
	if max <= 0 {
		max = 32
	}
	return &BatchingSaver{inner: inner, log: log, window: window, max: max}
}

// Save enqueues and returns; the window flusher persists.
func (b *BatchingSaver) Save(_ context.Context, tenantID string, p *path.Path) error {
	if tenantID == "" {
		return ErrNoTenant
	}
	b.mu.Lock()
	b.pending = append(b.pending, pendingPath{tenantID: tenantID, p: p})
	full := len(b.pending) >= b.max
	if b.timer == nil && !full {
		b.timer = time.AfterFunc(b.window, func() { b.Flush(context.Background()) })
	}
	b.mu.Unlock()
	if full {
		b.Flush(context.Background())
	}
	return nil
}

// Flush persists everything pending (one combined insert per table when the
// backend supports it). Safe to call concurrently.
func (b *BatchingSaver) Flush(ctx context.Context) {
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

// Latest flushes pending saves first (read-your-write), then delegates.
func (b *BatchingSaver) Latest(ctx context.Context, tenantID, target string) (*path.Path, bool, error) {
	b.Flush(ctx)
	return b.inner.Latest(ctx, tenantID, target)
}

// Close flushes and closes the backend.
func (b *BatchingSaver) Close() error {
	b.Flush(context.Background())
	return b.inner.Close()
}

// Lost reports paths dropped by failed flushes (should be 0).
func (b *BatchingSaver) Lost() uint64 { return b.lost.Load() }

// Flushes reports flush cycles (each ≤ 2 inserts on the CH backend).
func (b *BatchingSaver) Flushes() uint64 { return b.flushes.Load() }
