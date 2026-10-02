// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package pathstore

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// TestPathBatchFencePartitionsCoBatchedTenants is the pathstore half of the
// GAP-01 regression (docs/guardrails.md G7-1): when active tenants A and B have
// paths queued in the SAME write-behind window as an offboarding tenant C, the
// production WithTenantWriteFence(NewBatchingSaver(...)) flush must persist A's
// and B's paths and drop ONLY C's — one tenant's lifecycle state must never
// drop another tenant's write.
//
// Against baseline 72e7a2b this FAILS: the combined flush fenced the coalesced
// batch as a unit, so C's offboarding fence dropped the whole window (A and B
// persisted nothing).
func TestPathBatchFencePartitionsCoBatchedTenants(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, testsupport.PostgresDSN())
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	testsupport.LockPostgresPublicCatalog(t, pool)

	stamp := time.Now().UTC().UnixNano()
	tenantA := insertPathFenceTenant(ctx, t, pool, fmt.Sprintf("gap01-path-a-%d", stamp))
	tenantB := insertPathFenceTenant(ctx, t, pool, fmt.Sprintf("gap01-path-b-%d", stamp))
	tenantC := insertPathFenceTenant(ctx, t, pool, fmt.Sprintf("gap01-path-c-%d", stamp))
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants WHERE id IN ($1::uuid, $2::uuid, $3::uuid)`,
			tenantA, tenantB, tenantC,
		)
	})

	if err := commitPathEraseFence(ctx, pool, tenantC); err != nil {
		t.Fatalf("offboard tenant C: %v", err)
	}

	memory := NewMemory()
	// A 1h window with max 32 keeps every queued path pending until the explicit
	// Flush, so A, B and C coalesce into ONE combined flush — the production
	// write-behind batch.
	batched := NewBatchingSaver(
		memory,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		time.Hour,
		32,
	)
	store := WithTenantWriteFence(batched, tenancy.NewPostgresWriterFence(pool))
	t.Cleanup(func() { _ = store.Close() })

	// Enqueue in the same window (write-behind: each Save returns immediately).
	if err := store.Save(ctx, tenantA, pathFencePath("198.51.100.30")); err != nil {
		t.Fatalf("queue tenant A path: %v", err)
	}
	if err := store.Save(ctx, tenantB, pathFencePath("203.0.113.30")); err != nil {
		t.Fatalf("queue tenant B path: %v", err)
	}
	if err := store.Save(ctx, tenantC, pathFencePath("192.0.2.30")); err != nil {
		t.Fatalf("queue tenant C path: %v", err)
	}

	batched.Flush(ctx)

	if got := len(memory.forTenant(tenantA)); got != 1 {
		t.Fatalf("tenant A paths = %d, want 1 (dropped by offboarding C's fence?)", got)
	}
	if got := len(memory.forTenant(tenantB)); got != 1 {
		t.Fatalf("tenant B paths = %d, want 1 (dropped by offboarding C's fence?)", got)
	}
	if got := len(memory.forTenant(tenantC)); got != 0 {
		t.Fatalf("offboarding tenant C paths = %d, want 0", got)
	}
	// Exactly C's one queued path was dropped; A and B were stored.
	if got := batched.lostCount(); got != 1 {
		t.Fatalf("dropped (fenced) path count = %d, want 1 (only offboarding C)", got)
	}
}
