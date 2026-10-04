// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestStrictPreTenantAuthPoliciesAreEnforced replaces the former
// TestPreTenantAuthMigrationContract, which grepped 0070's SQL text. It proves
// the two properties that actually matter on a migrated database, reading live
// catalogs rather than source:
//
//	(A) the strict pre-tenant RLS is in force — AssertIsolationPosture (which runs
//	    assertStrictPreTenantPolicies over sessions, mcp_tokens, scim_tokens,
//	    agent_enroll_tokens, agent_identities and break_glass_grants) passes, and
//	    would FATAL on any regression to the old permissive "unset-GUC => all
//	    rows" shape or a dropped tenant_isolation policy; and
//	(B) the provider_* operations are EXECUTE-granted to probectl_provider and
//	    NOT to probectl_app — the exact forbidden grant the old grep guarded,
//	    read straight from pg_proc.proacl.
//
// Both survive any reformat of the migration (whitespace, reordered statements,
// renamed locals); the non-vacuity of assertStrictPreTenantPolicies itself is
// already pinned by the pure-unit TestStrictTenantPolicyExpression in tenancy.
func TestStrictPreTenantAuthPoliciesAreEnforced(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	// (A) The migrated DB has strict, enforceable pre-tenant policies.
	if err := tenancy.AssertIsolationPosture(ctx, pool); err != nil {
		t.Fatalf("migrated DB must have strict, enforceable pre-tenant policies: %v", err)
	}

	// (B) provider_* functions are provider-only: granted to probectl_provider,
	// never to probectl_app (read from the catalog ACL, not the migration text).
	for _, fn := range []string{
		"provider_revoke_agent_enroll_token",
		"provider_list_revoked_agent_identities",
	} {
		grantees := functionExecuteGrantees(ctx, t, pool, fn)
		if !grantees["probectl_provider"] {
			t.Errorf("%s must be EXECUTE-granted to probectl_provider; grantees=%v", fn, grantees)
		}
		if grantees["probectl_app"] {
			t.Errorf("%s must NOT be executable by probectl_app (provider-only); grantees=%v", fn, grantees)
		}
	}
}

// functionExecuteGrantees reads EXECUTE grantees straight from pg_proc.proacl
// (world-readable; no role membership needed). A function's owner always holds
// EXECUTE, so the result is a superset of the explicit grants — which is why the
// test asserts on the presence/absence of specific roles, not the exact set.
func functionExecuteGrantees(ctx context.Context, t *testing.T, pool *pgxpool.Pool, proname string) map[string]bool {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT r.rolname
		  FROM pg_proc p
		  JOIN pg_namespace n ON n.oid = p.pronamespace
		  CROSS JOIN LATERAL aclexplode(p.proacl) a
		  JOIN pg_roles r ON r.oid = a.grantee
		 WHERE n.nspname = 'public' AND p.proname = $1 AND a.privilege_type = 'EXECUTE'`, proname)
	if err != nil {
		t.Fatalf("read proacl for %s: %v", proname, err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			t.Fatal(err)
		}
		out[role] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate proacl for %s: %v", proname, err)
	}
	return out
}
