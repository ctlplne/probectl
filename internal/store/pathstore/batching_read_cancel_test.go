// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pathstore

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/path"
)

// gapBatchSaver is a fake inner Store that exercises the COALESCED cross-tenant
// flush path the production tenant write fence provides (SaveBatchPartitioned).
// Its combined insert FAILS CLOSED when its context is already canceled — the
// way a real backend request aborts — and otherwise records every path that
// actually reached it, so a test can tell "persisted" from "dropped".
type gapBatchSaver struct {
	mu        sync.Mutex
	persisted []PathItem
}

// SaveBatchPartitioned persists every eligible path (no tenant fenced) unless
// the context is already canceled, in which case the whole combined insert is
// aborted — exactly the situation GAP-02 is about: the batcher then counts the
// shared, cross-tenant batch lost.
func (s *gapBatchSaver) SaveBatchPartitioned(ctx context.Context, items []PathItem) (map[string]error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.persisted = append(s.persisted, items...)
	s.mu.Unlock()
	return nil, nil
}

func (s *gapBatchSaver) persistedTenants() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.persisted))
	for i := range s.persisted {
		out[i] = s.persisted[i].TenantID
	}
	return out
}

// Store interface — only the partitioned batch seam carries this test; the
// read methods ignore their context so the assertions isolate the flush.
func (*gapBatchSaver) Save(context.Context, string, *path.Path) error { return nil }

func (*gapBatchSaver) Latest(context.Context, string, string) (*path.Path, bool, error) {
	return nil, false, nil
}

func (*gapBatchSaver) History(context.Context, string, string, HistoryQuery) ([]Snapshot, error) {
	return nil, nil
}

func (*gapBatchSaver) Close() error { return nil }

func newGapBatchingSaver(t *testing.T, inner Store) *BatchingSaver {
	t.Helper()
	// A long window and spare batch room keep the queued path PENDING until a
	// read flushes it, so no timer/size autoflush races the assertions.
	b := NewBatchingSaver(inner, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour, 32)
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// TestBatchingSaverReadCancellationPreservesCrossTenantBatch is the GAP-02
// regression: a read-your-write flush drains the DEPLOYMENT-WIDE batch, so a
// reading tenant's canceled request must never abort it and drop ANOTHER
// tenant's queued path write (docs/guardrails.md G7-1). It fails before the
// batching.go fix (the shared flush ran under the reader's canceled context,
// so tenant B's path was counted lost and dropped) and passes after.
func TestBatchingSaverReadCancellationPreservesCrossTenantBatch(t *testing.T) {
	reads := map[string]func(*BatchingSaver, context.Context) error{
		"Latest": func(b *BatchingSaver, ctx context.Context) error {
			_, _, err := b.Latest(ctx, "tenant-a", "10.0.0.1")
			return err
		},
		"History": func(b *BatchingSaver, ctx context.Context) error {
			_, err := b.History(ctx, "tenant-a", "10.0.0.1", HistoryQuery{Limit: 50})
			return err
		},
	}
	for name, doRead := range reads {
		t.Run(name, func(t *testing.T) {
			inner := &gapBatchSaver{}
			batching := newGapBatchingSaver(t, inner)

			// Tenant B queues a path write. Write-behind: it sits in the shared
			// pending batch, not yet persisted.
			if err := batching.Save(context.Background(), "tenant-b", &path.Path{}); err != nil {
				t.Fatalf("queue tenant-b path: %v", err)
			}
			if got := batching.saved.Load(); got != 0 {
				t.Fatalf("precondition: tenant-b path flushed before any read (saved=%d)", got)
			}

			// Tenant A issues a read whose request context is ALREADY canceled
			// (client disconnect / timeout). Its read-your-write flush drains the
			// shared batch — which still holds tenant B's queued write.
			canceledCtx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := doRead(batching, canceledCtx); err != nil {
				t.Fatalf("%s with a canceled context: %v", name, err)
			}

			// G7-1: tenant A's canceled read must not have dropped tenant B's
			// queued write from the shared, cross-tenant batch.
			if tenants := inner.persistedTenants(); len(tenants) != 1 || tenants[0] != "tenant-b" {
				t.Fatalf("tenant-a's canceled read dropped tenant-b's queued write: persisted=%v, want [tenant-b] (G7-1: one tenant's canceled read must not drop another tenant's writes)", tenants)
			}
			if lost := batching.lostCount(); lost != 0 {
				t.Fatalf("lostCount=%d after a canceled read, want 0 (the shared cross-tenant batch must survive the reader's cancellation)", lost)
			}
		})
	}
}

// TestBatchingSaverLiveReadStillFlushesPending is the non-vacuity guard: a
// normal (non-canceled) read must STILL flush pending saves and read-your-write
// — proving the cancellation fix did not simply stop the read path from
// flushing.
func TestBatchingSaverLiveReadStillFlushesPending(t *testing.T) {
	inner := &gapBatchSaver{}
	batching := newGapBatchingSaver(t, inner)

	if err := batching.Save(context.Background(), "tenant-b", &path.Path{}); err != nil {
		t.Fatalf("queue tenant-b path: %v", err)
	}
	if _, _, err := batching.Latest(context.Background(), "tenant-a", "10.0.0.1"); err != nil {
		t.Fatalf("Latest with a live context: %v", err)
	}
	if tenants := inner.persistedTenants(); len(tenants) != 1 || tenants[0] != "tenant-b" {
		t.Fatalf("live Latest did not flush the pending write: persisted=%v, want [tenant-b]", tenants)
	}
	if lost := batching.lostCount(); lost != 0 {
		t.Fatalf("lostCount=%d after a live read, want 0", lost)
	}
}
