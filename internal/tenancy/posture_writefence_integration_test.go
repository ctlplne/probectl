// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

// TEN-02 (docs/guardrails.md G7-1): the tenant request-path role (probectl_app)
// must hold ONLY SELECT on provider-owned per-tenant config tables, never
// INSERT/UPDATE/DELETE. These assertions run against REAL PostgreSQL grants on a
// freshly migrated database — there is no fake catalog here, because the whole
// point is the privilege the database actually enforces. Built under both the
// `integration` and `isolation` tags so it runs in `make test-integration` and
// in the dedicated cross-tenant-isolation gate alongside the other posture
// checks.
package tenancy_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// ten02FencedTables are the provider-owned config tables the app role must not
// write (it keeps only SELECT, the self-view). Mirrors posture.go's
// appWriteFencedTables; kept as an independent literal so the test fails if the
// production set silently shrinks.
var ten02FencedTables = []string{
	"tenant_branding",
	"tenant_fairness",
	"tenant_governance",
	"tenant_quotas",
	"usage_records",
}

// ten02TenantWritableTables are provider-owned-for-silo tables that nonetheless
// carry a legitimate app-role tenant self-service write (retention/erasure is a
// core compliance right; BYOK key rotation is tenant-driven). The fence must NOT
// touch these — this guards against over-revoking.
var ten02TenantWritableTables = []string{
	"tenant_retention",
	"tenant_keys",
}

func ten02DSN() string {
	if v := os.Getenv("PROBECTL_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://probectl@localhost:5432/postgres?sslmode=disable"
}

// ten02Setup connects and applies every migration (schema + RLS + the
// probectl_app role + the 0111 write fence), skipping when no database is
// available (or failing in CI, which sets PROBECTL_TEST_REQUIRE_SERVICES=1).
func ten02Setup(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, ten02DSN())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	return pool
}

// appHasTablePrivilege reads the EFFECTIVE privilege probectl_app holds, from
// inside a transaction that has assumed that role — exactly the runtime posture.
// The 3-arg has_table_privilege with the role named is the same form the boot
// posture check uses, and is the acceptance criterion verbatim.
func appHasTablePrivilege(ctx context.Context, t *testing.T, pool *pgxpool.Pool, table, priv string) bool {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+tenancy.AppRole); err != nil {
		t.Fatalf("assume app role: %v", err)
	}
	var has bool
	if err := tx.QueryRow(ctx,
		"SELECT has_table_privilege('probectl_app', $1, $2)", "public."+table, priv).Scan(&has); err != nil {
		t.Fatalf("has_table_privilege(%s,%s): %v", table, priv, err)
	}
	return has
}

// TestTEN02AppRoleWriteFenceOnProviderTables is the regression lock for the
// finding: on a fresh migrated DB the app role holds NO write on any
// provider-owned config table, still holds SELECT for the self-view, and still
// holds write on the two genuinely tenant-writable tables.
func TestTEN02AppRoleWriteFenceOnProviderTables(t *testing.T) {
	ctx := context.Background()
	pool := ten02Setup(ctx, t)
	defer pool.Close()

	for _, table := range ten02FencedTables {
		for _, priv := range []string{"INSERT", "UPDATE", "DELETE"} {
			if appHasTablePrivilege(ctx, t, pool, table, priv) {
				t.Errorf("has_table_privilege('probectl_app','%s','%s') = true, want false (TEN-02: provider-owned table must be SELECT-only for the app role)",
					table, priv)
			}
		}
		if !appHasTablePrivilege(ctx, t, pool, table, "SELECT") {
			t.Errorf("has_table_privilege('probectl_app','%s','SELECT') = false, want true (the self-view must survive the fence)", table)
		}
	}

	// Guard against over-revoking: the tenant's own retention policy and key
	// rotation legitimately write these under the app role.
	for _, table := range ten02TenantWritableTables {
		for _, priv := range []string{"INSERT", "UPDATE"} {
			if !appHasTablePrivilege(ctx, t, pool, table, priv) {
				t.Errorf("has_table_privilege('probectl_app','%s','%s') = false, want true (this table has a legitimate app-role tenant self-service write; the fence must not touch it)",
					table, priv)
			}
		}
	}
}

// TestTEN02PostureFailsWhenAppRoleRegainsWrite proves the boot self-check is not
// vacuous: it passes on the correctly-fenced DB and FATALs (returns a startup
// error) the moment probectl_app regains write on a provider-owned table.
func TestTEN02PostureFailsWhenAppRoleRegainsWrite(t *testing.T) {
	ctx := context.Background()
	pool := ten02Setup(ctx, t)
	// Registered first so it runs LAST (Cleanups are LIFO); the fence-restore
	// below runs before the pool closes.
	t.Cleanup(pool.Close)

	if err := tenancy.AssertIsolationPosture(ctx, pool); err != nil {
		t.Fatalf("posture must pass on a correctly-fenced DB: %v", err)
	}

	// Re-add the exact write grant 0111 removed, then prove boot refuses to start.
	if _, err := pool.Exec(ctx, "GRANT UPDATE ON public.tenant_fairness TO probectl_app"); err != nil {
		t.Fatalf("re-add write grant: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			"REVOKE INSERT, UPDATE, DELETE ON public.tenant_fairness FROM probectl_app"); err != nil {
			t.Errorf("restore fence: %v", err)
		}
	})

	err := tenancy.AssertIsolationPosture(ctx, pool)
	if err == nil {
		t.Fatal("posture must FATAL when probectl_app regains write on tenant_fairness, but it passed (TEN-02 guard absent or vacuous)")
	}
	if !strings.Contains(err.Error(), "tenant_fairness") {
		t.Fatalf("posture error must name the offending table; got: %v", err)
	}

	// And it passes again once the fence is restored (proves the grant was the
	// sole cause).
	if _, err := pool.Exec(ctx, "REVOKE INSERT, UPDATE, DELETE ON public.tenant_fairness FROM probectl_app"); err != nil {
		t.Fatalf("restore fence: %v", err)
	}
	if err := tenancy.AssertIsolationPosture(ctx, pool); err != nil {
		t.Fatalf("posture must pass again once the fence is restored: %v", err)
	}
}
