// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tsdb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// TestTSDBBatchFencePartitionsConcurrentTenants is the GAP-01 regression
// (docs/guardrails.md G7-1): when active tenants A and B write in the SAME
// batch window as an offboarding tenant C, the production
// WithTenantWriteFence(NewBatchingWriter(...)) must store A's and B's series
// and reject ONLY C — one tenant's lifecycle state must never decide another
// tenant's write.
//
// It reproduces the exact coalescing the ingest hot path does: a maxSeries of
// three with an effectively infinite window means the single shared batch
// flushes precisely when all three concurrent callers have joined it, so A, B
// and C are fenced as one coalesced multi-tenant remote-write batch.
//
// Against baseline 72e7a2b this FAILS: the fence was checked on the coalesced
// batch as a unit, so C's offboarding fence rejected A and B too (0 series
// stored). It also asserts A's and B's results never leak C's UUID or status.
func TestTSDBBatchFencePartitionsConcurrentTenants(t *testing.T) {
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
	tenantA := insertTSDBFenceTenant(ctx, t, pool, fmt.Sprintf("gap01-tsdb-a-%d", stamp))
	tenantB := insertTSDBFenceTenant(ctx, t, pool, fmt.Sprintf("gap01-tsdb-b-%d", stamp))
	tenantC := insertTSDBFenceTenant(ctx, t, pool, fmt.Sprintf("gap01-tsdb-c-%d", stamp))
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants WHERE id IN ($1::uuid, $2::uuid, $3::uuid)`,
			tenantA, tenantB, tenantC,
		)
	})

	// C begins offboarding and carries the durable erasure fence, exactly as it
	// would mid-erasure while its agents' results are still in flight.
	if err := commitTSDBEraseFence(ctx, pool, tenantC); err != nil {
		t.Fatalf("offboard tenant C: %v", err)
	}

	memory := NewMemory()
	// maxSeries=3 with a 1h window: the single shared batch flushes exactly when
	// all three concurrent single-series callers have joined it, so A, B and C
	// are coalesced into ONE multi-tenant remote-write batch.
	writer := WithTenantWriteFence(
		NewBatchingWriter(memory, 3, time.Hour),
		tenancy.NewPostgresWriterFence(pool),
	)
	t.Cleanup(func() { _ = writer.Close() })

	type result struct {
		tenant string
		err    error
	}
	results := make(chan result, 3)
	for _, tenantID := range []string{tenantA, tenantB, tenantC} {
		go func(id string) {
			results <- result{tenant: id, err: writer.Write(ctx, []Series{tsdbFenceSeries(id, "gap01")})}
		}(tenantID)
	}

	errByTenant := map[string]error{}
	for i := 0; i < 3; i++ {
		select {
		case r := <-results:
			errByTenant[r.tenant] = r.err
		case <-ctx.Done():
			t.Fatalf("coalesced batch did not flush: %v", ctx.Err())
		}
	}

	// A and B are active: their writes must SUCCEED despite sharing the batch
	// with offboarding C.
	if err := errByTenant[tenantA]; err != nil {
		t.Fatalf("tenant A write failed while co-batched with offboarding C: %v", err)
	}
	if err := errByTenant[tenantB]; err != nil {
		t.Fatalf("tenant B write failed while co-batched with offboarding C: %v", err)
	}
	// C is offboarding: only C is rejected.
	if err := errByTenant[tenantC]; !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf("tenant C write error = %v, want ErrTenantWritesFenced", err)
	}

	// The eligible tenants' series are stored; the fenced tenant's are not.
	if got := memory.Query("probectl_tsdb_fence", map[string]string{TenantLabel: tenantA}); len(got) != 1 {
		t.Fatalf("tenant A stored series = %d, want 1", len(got))
	}
	if got := memory.Query("probectl_tsdb_fence", map[string]string{TenantLabel: tenantB}); len(got) != 1 {
		t.Fatalf("tenant B stored series = %d, want 1", len(got))
	}
	if got := memory.Query("probectl_tsdb_fence", map[string]string{TenantLabel: tenantC}); len(got) != 0 {
		t.Fatalf("offboarding tenant C stored series = %d, want 0", len(got))
	}

	// A fenced-tenant error must never surface C's UUID or status to a co-batched
	// caller (G7-1: no cross-tenant information leak).
	for _, id := range []string{tenantA, tenantB} {
		if err := errByTenant[id]; err != nil {
			if strings.Contains(err.Error(), tenantC) || strings.Contains(err.Error(), "status=offboarding") {
				t.Fatalf("tenant %s error leaked co-batched tenant C identity/status: %v", id, err)
			}
		}
	}
}
