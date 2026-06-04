//go:build isolation

// Cross-tenant isolation gate — the permanent CI gate (CLAUDE.md §7 guardrail 1).
// Seeded as a placeholder in S0; this is the real suite from S2.
//
// It proves isolation at BOTH layers required by PRD §3.2 ("a missing application
// check cannot leak data"): the repository (query) layer scopes reads, and a raw,
// predicate-free query still returns only the caller's rows because Row-Level
// Security is enforced by the database. It also proves fail-closed behavior and
// that the provider plane is a separate, cross-tenant domain.
package tenancy_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/migrations"
)

func dsn() string {
	if v := os.Getenv("PROBECTL_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://probectl@localhost:5432/postgres?sslmode=disable"
}

// setup connects, applies migrations (schema + RLS + the probectl_app role), and
// skips when no database is available.
func setup(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	return pool
}

func TestCrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	tenants := store.NewTenants(pool)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	ta, err := tenants.Create(ctx, "iso-a-"+suffix, "Iso A")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tb, err := tenants.Create(ctx, "iso-b-"+suffix, "Iso B")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}

	orgs := store.Organizations{}
	var bOrg string
	mustScope(ctx, t, pool, ta.ID, func(ctx context.Context, s tenancy.Scope) error {
		_, err := orgs.Create(ctx, s, "a-org", "A Org")
		return err
	})
	mustScope(ctx, t, pool, tb.ID, func(ctx context.Context, s tenancy.Scope) error {
		o, err := orgs.Create(ctx, s, "b-org", "B Org")
		if err == nil {
			bOrg = o.ID
		}
		return err
	})

	mustScope(ctx, t, pool, ta.ID, func(ctx context.Context, s tenancy.Scope) error {
		// Query layer: the repository sees only tenant A's organization.
		list, err := orgs.List(ctx, s)
		if err != nil {
			return err
		}
		if len(list) != 1 || list[0].Slug != "a-org" || list[0].TenantID != ta.ID {
			t.Errorf("tenant A org list = %+v, want exactly its own org", list)
		}
		// Storage layer: a RAW, predicate-free query still returns only A's rows.
		var raw int
		if err := s.Q.QueryRow(ctx, "SELECT count(*) FROM organizations").Scan(&raw); err != nil {
			return err
		}
		if raw != 1 {
			t.Errorf("raw unscoped org count in tenant A = %d, want 1 (RLS LEAK)", raw)
		}
		// Tenant B's organization must be invisible to A.
		if _, err := orgs.Get(ctx, s, bOrg); err == nil {
			t.Error("tenant A could read tenant B's organization (CROSS-TENANT LEAK)")
		}
		return nil
	})

	// The provider plane (no tenant scope) sees all tenants.
	all, err := tenants.List(ctx)
	if err != nil {
		t.Fatalf("provider list: %v", err)
	}
	if !containsTenant(all, ta.ID) || !containsTenant(all, tb.ID) {
		t.Error("provider tenant list should include both tenants")
	}

	// Fail closed: a tenant-scoped operation with no tenant in context errors.
	err = tenancy.InTenant(ctx, pool, func(context.Context, tenancy.Scope) error { return nil })
	if !errors.Is(err, tenancy.ErrNoTenant) {
		t.Errorf("InTenant without a tenant = %v, want ErrNoTenant", err)
	}
}

func mustScope(ctx context.Context, t *testing.T, pool *pgxpool.Pool, tenantID string, fn func(context.Context, tenancy.Scope) error) {
	t.Helper()
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool, fn); err != nil {
		t.Fatalf("InTenant(%s): %v", tenantID, err)
	}
}

func containsTenant(ts []store.Tenant, id string) bool {
	for i := range ts {
		if ts[i].ID == id {
			return true
		}
	}
	return false
}
