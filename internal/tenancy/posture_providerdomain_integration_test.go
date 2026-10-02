// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

// GAP-03 (docs/guardrails.md G7-1): the tenant request-path role (probectl_app)
// must hold NO privilege — not even SELECT — on the provider-DOMAIN tables
// (operator sessions, the provisioning ledger, the provider master brand).
// These assertions run against REAL PostgreSQL grants on a freshly migrated
// database, because the whole point is the privilege the database actually
// enforces. Built under both the `integration` and `isolation` tags, like the
// TEN-02 write-fence suite it sits beside (and whose ten02Setup /
// appHasTablePrivilege helpers it reuses).
package tenancy_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// gap03ProviderDomainTables are the provider-DOMAIN tables the app role must not
// touch AT ALL. Kept as an independent literal (mirrors posture.go's
// providerDomainNoAppAccessTables) so the test fails if the production set
// silently shrinks.
var gap03ProviderDomainTables = []string{
	"provider_sessions",
	"tenant_provisioning",
	"provider_branding",
}

// gap03ControlPlaneTables look provider-adjacent but are deployment-wide
// CONTROL-plane infrastructure with a legitimate app-role writer and explicit
// grants (migrations 0041 / 0054). The GAP-03 fence must NOT touch them — this
// guards against over-revoking and breaking agent enrollment / lease
// coordination.
var gap03ControlPlaneTables = []string{
	"agent_ca",
	"cluster_singleton_leases",
}

// TestGAP03ProviderDomainTablesNoAppAccess is the regression lock: on a fresh
// migrated DB the app role holds NO privilege of any kind on a provider-domain
// table, yet still holds write on the control-plane tables that legitimately
// need it.
func TestGAP03ProviderDomainTablesNoAppAccess(t *testing.T) {
	ctx := context.Background()
	pool := ten02Setup(ctx, t)
	defer pool.Close()

	for _, table := range gap03ProviderDomainTables {
		for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
			if appHasTablePrivilege(ctx, t, pool, table, priv) {
				t.Errorf("has_table_privilege('probectl_app','%s','%s') = true, want false (GAP-03: a provider-domain table must be entirely unreachable by the tenant app role)",
					table, priv)
			}
		}
	}

	// Guard against over-revoking: these carry a legitimate control-plane write.
	for _, table := range gap03ControlPlaneTables {
		for _, priv := range []string{"INSERT", "UPDATE"} {
			if !appHasTablePrivilege(ctx, t, pool, table, priv) {
				t.Errorf("has_table_privilege('probectl_app','%s','%s') = false, want true (deployment-wide control-plane infrastructure; the GAP-03 fence must not touch it)",
					table, priv)
			}
		}
	}
}

// TestGAP03AppRoleProbeDeniedOnProviderDomain is the acceptance criterion
// verbatim: a provider-domain probe transaction, run as probectl_app, is refused
// with "permission denied" on every statement (SELECT/INSERT/UPDATE/DELETE).
func TestGAP03AppRoleProbeDeniedOnProviderDomain(t *testing.T) {
	ctx := context.Background()
	pool := ten02Setup(ctx, t)
	defer pool.Close()

	stmts := []struct{ name, sql string }{
		{"SELECT", `SELECT 1 FROM provider_sessions LIMIT 1`},
		{"INSERT", `INSERT INTO provider_sessions (token_hash, operator_id, expires_at, last_activity_at) VALUES ('x', gen_random_uuid(), now(), now())`},
		{"UPDATE", `UPDATE provider_sessions SET last_activity_at = now()`},
		{"DELETE", `DELETE FROM provider_sessions`},
	}
	for _, s := range stmts {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+tenancy.AppRole); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("assume app role: %v", err)
		}
		_, execErr := tx.Exec(ctx, s.sql)
		_ = tx.Rollback(ctx)
		if execErr == nil {
			t.Errorf("%s on provider_sessions as %s succeeded, want permission denied (GAP-03)", s.name, tenancy.AppRole)
			continue
		}
		if !isPermissionDenied(execErr) {
			t.Errorf("%s on provider_sessions as %s: error = %v, want a permission-denied error (GAP-03)", s.name, tenancy.AppRole, execErr)
		}
	}
}

// isPermissionDenied reports whether err is PostgreSQL's insufficient_privilege
// (SQLSTATE 42501), falling back to the message text for non-PgError wrappers.
func isPermissionDenied(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "42501"
	}
	return strings.Contains(strings.ToLower(err.Error()), "permission denied")
}

// TestGAP03PostureFailsWhenAppRegainsProviderDomainAccess proves the boot
// self-check is not vacuous: it passes on the correctly-fenced DB and FATALs
// (returns a startup error) the moment probectl_app regains ANY privilege —
// even a bare SELECT — on a provider-domain table.
func TestGAP03PostureFailsWhenAppRegainsProviderDomainAccess(t *testing.T) {
	ctx := context.Background()
	pool := ten02Setup(ctx, t)
	t.Cleanup(pool.Close)

	if err := tenancy.AssertIsolationPosture(ctx, pool); err != nil {
		t.Fatalf("posture must pass on a correctly-fenced DB: %v", err)
	}

	// Re-add a grant 0112 removed. Even SELECT is forbidden on a provider-domain
	// table, so a bare SELECT grant must trip the guard.
	if _, err := pool.Exec(ctx, "GRANT SELECT ON public.provider_sessions TO probectl_app"); err != nil {
		t.Fatalf("re-add grant: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			"REVOKE ALL PRIVILEGES ON public.provider_sessions FROM probectl_app"); err != nil {
			t.Errorf("restore fence: %v", err)
		}
	})

	err := tenancy.AssertIsolationPosture(ctx, pool)
	if err == nil {
		t.Fatal("posture must FATAL when probectl_app regains any privilege on provider_sessions, but it passed (GAP-03 guard absent or vacuous)")
	}
	if !strings.Contains(err.Error(), "provider_sessions") {
		t.Fatalf("posture error must name the offending table; got: %v", err)
	}

	// And it passes again once the fence is restored (proves the grant was the
	// sole cause).
	if _, err := pool.Exec(ctx, "REVOKE ALL PRIVILEGES ON public.provider_sessions FROM probectl_app"); err != nil {
		t.Fatalf("restore fence: %v", err)
	}
	if err := tenancy.AssertIsolationPosture(ctx, pool); err != nil {
		t.Fatalf("posture must pass again once the fence is restored: %v", err)
	}
}
