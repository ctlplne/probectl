// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package fairness

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
	"github.com/imfeelingtheagi/probectl/migrations"
)

// The S-T7 integration leg (live Postgres): the fairness policy round-trips
// through tenant_fairness via the provider role, unset fields stay NULL
// (deployment defaults), the gate's source sees the override, and the
// TENANT-side read path (RLS) lets a tenant see only its own policy — the
// /v1/fairness self-view contract.
func itPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testsupport.PostgresDSN()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
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
	stamp := time.Now().UTC().Format("20060102150405.000000000")
	tnA := itTenant(t, pool, "it-fair-a-"+stamp)
	tnB := itTenant(t, pool, "it-fair-b-"+stamp)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_fairness WHERE tenant_id IN ($1, $2)`, tnA, tnB)
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id::text IN ($1, $2)`, tnA, tnB)
	})
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

	// The gate consumes the stored override (the fetch is asynchronous by
	// design — admission never blocks on Postgres — so poll with a sleep).
	g := NewGate(Policy{}, store)
	g.EffectivePolicy(ctx, tnA) // schedules the refresh
	deadline := time.Now().Add(5 * time.Second)
	for g.EffectivePolicy(ctx, tnA).ResultsPerSec != 100 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := g.EffectivePolicy(ctx, tnA); got.ResultsPerSec != 100 {
		t.Fatalf("gate must see the stored override: %+v", got)
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
