//go:build integration

package fairness

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/migrations"
)

// The S-T7 integration leg (live Postgres): the fairness policy round-trips
// through tenant_fairness via the provider role, unset fields stay NULL
// (deployment defaults), the gate's source sees the override, and the
// TENANT-side read path (RLS) lets a tenant see only its own policy — the
// /v1/fairness self-view contract.
func itPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("PROBECTL_TEST_POSTGRES")
	if dsn == "" {
		dsn = "postgres://probectl:probectl@localhost:5432/probectl"
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

func itTenant(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tenants (slug, name) VALUES ($1, $1)
		 ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id::text`, slug).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPolicyStorePG(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()
	tnA := itTenant(t, pool, "it-fair-a")
	tnB := itTenant(t, pool, "it-fair-b")
	store := NewPGStore(pool)

	// No row yet: ok=false.
	if _, ok, err := store.PolicyFor(ctx, tnA); err != nil || ok {
		t.Fatalf("missing row: ok=%v err=%v", ok, err)
	}
	// Upsert with some fields unset (0 -> NULL -> deployment default).
	in := Policy{ResultsPerSec: 250, QueriesPerMin: 120}
	if err := store.Upsert(ctx, tnA, in, "op@msp.example"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.PolicyFor(ctx, tnA)
	if err != nil || !ok || got.ResultsPerSec != 250 || got.QueriesPerMin != 120 || got.FlowEventsPerSec != 0 {
		t.Fatalf("round-trip: %+v ok=%v err=%v", got, ok, err)
	}
	// Update narrows the bound; All() lists it.
	in.ResultsPerSec = 100
	if err := store.Upsert(ctx, tnA, in, "op@msp.example"); err != nil {
		t.Fatal(err)
	}
	all, err := store.All(ctx)
	if err != nil || all[tnA].ResultsPerSec != 100 {
		t.Fatalf("all: %+v err=%v", all, err)
	}

	// The gate consumes the stored override.
	g := NewGate(Policy{}, store)
	g.EffectivePolicy(ctx, tnA)
	deadline := 0
	for g.EffectivePolicy(ctx, tnA).ResultsPerSec != 100 && deadline < 2000 {
		deadline++
	}
	if g.EffectivePolicy(ctx, tnA).ResultsPerSec != 100 {
		t.Fatalf("gate must see the stored override: %+v", g.EffectivePolicy(ctx, tnA))
	}

	// Tenant-side RLS: tenant B reads its OWN policy view — A's row is
	// invisible (count over the table under B's scope = 0).
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tnB)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		var n int64
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM tenant_fairness`).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("tenant B must not see other tenants' fairness rows: %d", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
