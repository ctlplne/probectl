//go:build integration

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package governance

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/govern"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/migrations"
)

// The S-EE3 integration leg (live Postgres): the governance policy round-trips
// through tenant_governance via the provider role (classification overrides +
// redaction floor + redact-export), the resolver feeds the core govern seam,
// and tenant-side RLS confines a tenant to its OWN policy row.
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

func TestGovernancePolicyRoundTripPG(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()
	tnA := itTenant(t, pool, "it-gov-a")
	tnB := itTenant(t, pool, "it-gov-b")
	store := NewStore(pool)

	// No row → defaults.
	if _, ok, err := store.PolicyFor(ctx, tnA); err != nil || ok {
		t.Fatalf("missing row: ok=%v err=%v", ok, err)
	}

	// Upsert a policy with a classification override + redaction floor.
	in := govern.Policy{
		Overrides:    map[govern.Category]govern.Class{govern.CatHostname: govern.ClassPII},
		RedactFrom:   govern.ClassConfidential,
		RedactExport: true,
	}
	if err := store.Upsert(ctx, tnA, in, "op@msp.example"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.PolicyFor(ctx, tnA)
	if err != nil || !ok {
		t.Fatalf("read back: ok=%v err=%v", ok, err)
	}
	if got.RedactFrom != govern.ClassConfidential || !got.RedactExport ||
		got.Overrides[govern.CatHostname] != govern.ClassPII {
		t.Fatalf("policy round-trip: %+v", got)
	}

	// The resolver feeds the core seam: hostname is now PII for tnA, so it
	// redacts under the merged policy.
	govern.SetSource(store)
	defer govern.Reset()
	pol := govern.PolicyFor(ctx, tnA)
	if pol.StrategyFor(govern.CatHostname) == govern.StrategyNone {
		t.Fatal("re-classified hostname must redact via the resolver")
	}

	// Update narrows the floor; no override.
	if err := store.Upsert(ctx, tnA, govern.Policy{RedactFrom: govern.ClassPII}, "op@msp.example"); err != nil {
		t.Fatal(err)
	}
	got, _, _ = store.PolicyFor(ctx, tnA)
	if got.RedactFrom != govern.ClassPII || len(got.Overrides) != 0 {
		t.Fatalf("update: %+v", got)
	}

	// Tenant-side RLS: tenant B sees only its OWN governance row.
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tnB)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		var n int64
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM tenant_governance`).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("tenant B must not see other tenants' governance rows: %d", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
