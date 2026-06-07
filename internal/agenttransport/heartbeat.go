package agenttransport

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// heartbeatBatcher coalesces per-agent heartbeats into one multi-row UPDATE
// per tenant per window (Sprint 14, SCALE-012). The RPC records the beat and
// returns immediately; liveness lag is bounded by the window (default 2s —
// far below the 30s heartbeat interval). nil batcher = the old synchronous
// per-RPC UPDATE (unit tests, minimal servers).
type heartbeatBatcher struct {
	pool   *pgxpool.Pool
	log    *slog.Logger
	window time.Duration

	mu      sync.Mutex
	pending map[string]map[string]struct{} // tenant -> agent ids

	flushed func(n int) // test seam (optional)
}

const defaultHeartbeatWindow = 2 * time.Second

func newHeartbeatBatcher(pool *pgxpool.Pool, log *slog.Logger, window time.Duration) *heartbeatBatcher {
	if window <= 0 {
		window = defaultHeartbeatWindow
	}
	return &heartbeatBatcher{pool: pool, log: log, window: window, pending: map[string]map[string]struct{}{}}
}

// record buffers one heartbeat (cheap; the RPC path).
func (h *heartbeatBatcher) record(tenantID, agentID string) {
	h.mu.Lock()
	m := h.pending[tenantID]
	if m == nil {
		m = map[string]struct{}{}
		h.pending[tenantID] = m
	}
	m[agentID] = struct{}{}
	h.mu.Unlock()
}

// run flushes every window until ctx is done (one final flush on the way out).
func (h *heartbeatBatcher) run(ctx context.Context) {
	t := time.NewTicker(h.window)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			h.flush(context.Background()) // final drain (bounded by pool timeouts)
			return
		case <-t.C:
			h.flush(ctx)
		}
	}
}

// flush issues one batched UPDATE per tenant. Failures re-buffer the beats —
// liveness is eventually consistent, never silently stale forever.
func (h *heartbeatBatcher) flush(ctx context.Context) {
	h.mu.Lock()
	batch := h.pending
	h.pending = map[string]map[string]struct{}{}
	h.mu.Unlock()

	total := 0
	for tenantID, agents := range batch {
		ids := make([]string, 0, len(agents))
		for id := range agents {
			ids = append(ids, id)
		}
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), h.pool,
			func(ctx context.Context, s tenancy.Scope) error {
				return (store.Agents{}).HeartbeatBatch(ctx, s, ids)
			})
		if err != nil {
			h.log.Warn("heartbeat batch flush failed (re-buffering)",
				"tenant", tenantID, "agents", len(ids), "error", err.Error())
			h.mu.Lock()
			m := h.pending[tenantID]
			if m == nil {
				m = map[string]struct{}{}
				h.pending[tenantID] = m
			}
			for _, id := range ids {
				m[id] = struct{}{}
			}
			h.mu.Unlock()
			continue
		}
		total += len(ids)
	}
	if h.flushed != nil && total > 0 {
		h.flushed(total)
	}
}
