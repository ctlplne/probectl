//go:build integration

package perf

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/migrations"
)

func integrationDSN() string {
	if v := os.Getenv("PROBECTL_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable"
}

// Pooled multi-tenant smoke parameters: many tenants sharing the pooled Postgres
// stores, each owning the same number of rows, queried concurrently. Sized as a
// CI smoke (a few thousand rows, a couple hundred queries) — not a soak.
const (
	pooledTenants     = 20
	pooledRowsPerTen  = 100
	pooledQueryReps   = 10
	pooledConcurrency = 16
)

// TestPooledMultiTenant is the S18a pooled smoke: K tenants share the stores;
// every tenant-scoped query must see EXACTLY its own rows (isolation under load —
// the first place a pooled-cardinality or RLS-cost problem would surface) and the
// p95 query latency must stay under the GA ceiling.
func TestPooledMultiTenant(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, integrationDSN(), 24, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		t.Skipf("no database available: %v", err)
	}
	t.Cleanup(db.Close)
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	// Provision K fresh tenants and seed each with the same number of tests. Each
	// tenant's rows are written in a single tenant-scoped transaction (fast seed).
	run := time.Now().UnixNano()
	tenants := make([]tenancy.ID, 0, pooledTenants)
	for i := 0; i < pooledTenants; i++ {
		tn, err := store.NewTenants(db.Pool()).Create(ctx,
			fmt.Sprintf("perf-%d-%d", run, i), fmt.Sprintf("perf tenant %d", i))
		if err != nil {
			t.Fatalf("create tenant %d: %v", i, err)
		}
		id := tenancy.ID(tn.ID)
		seedTenant(ctx, t, db, id, pooledRowsPerTen)
		tenants = append(tenants, id)
	}

	ops := PooledOps{
		CountRows: func(ctx context.Context, tenant tenancy.ID) (int, error) {
			var n int
			err := tenancy.InTenant(tenancy.WithTenant(ctx, tenant), db.Pool(),
				func(ctx context.Context, sc tenancy.Scope) error {
					list, e := store.Tests{}.List(ctx, sc)
					n = len(list)
					return e
				})
			return n, err
		},
	}

	rep, err := DrivePooled(ctx, tenants, pooledRowsPerTen, ops,
		PooledConfig{QueryReps: pooledQueryReps, Concurrency: pooledConcurrency})
	if err != nil {
		t.Fatalf("drive pooled: %v", err)
	}
	t.Logf("%s", rep)

	if !rep.IsolationOK {
		t.Fatalf("CROSS-TENANT ISOLATION FAILURE under load: %d/%d tenant-scoped queries saw the wrong row count",
			rep.Mismatches, rep.Queries)
	}
	if v := M6Baseline().CheckPooled(rep); len(v) > 0 {
		t.Errorf("pooled baseline violated: %v", v)
	}
}

func seedTenant(ctx context.Context, t *testing.T, db *store.DB, tenant tenancy.ID, rows int) {
	t.Helper()
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenant), db.Pool(),
		func(ctx context.Context, sc tenancy.Scope) error {
			for i := 0; i < rows; i++ {
				_, e := store.Tests{}.Create(ctx, sc, store.TestInput{
					Name:            fmt.Sprintf("perf-test-%d", i),
					Type:            "icmp",
					Target:          "1.1.1.1",
					IntervalSeconds: 30,
					Enabled:         true,
				})
				if e != nil {
					return e
				}
			}
			return nil
		})
	if err != nil {
		t.Fatalf("seed tenant %s: %v", tenant, err)
	}
}
