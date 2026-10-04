// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package tenancy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func mustExec(ctx context.Context, t *testing.T, pool *pgxpool.Pool, sql string) {
	t.Helper()
	if _, err := pool.Exec(ctx, sql); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// TestProviderPolicyGuardIsCatalogBasedAndPermissiveOnly (DPR-122) exercises
// assertProviderPoliciesAreScoped against real catalogs instead of grepping its
// SQL. It plants a tenant-owned probe table the application role has NO grant
// on, carrying a PERMISSIVE USING(true) provider SELECT policy, and asserts the
// guard both SEES it (catalog-based, not privilege-filtered information_schema)
// and treats only PERMISSIVE policies as grants:
//
//   - Reverting the guard's column lookup to information_schema.columns hides the
//     probe's tenant_id (the app role has no grant), so the policy is excluded,
//     no FATAL fires, and the first assertion fails.
//   - Dropping the `permissive = 'PERMISSIVE'` filter flags the RESTRICTIVE
//     variant as an unconstrained grant, so the second assertion fails.
//
// The probe name is not in providerManagedTables, is not a canonical t_<hex>
// silo schema, and carries no application-role policy, so it trips ONLY the
// provider-policy check — which is what lets the RESTRICTIVE case pass cleanly.
func TestProviderPolicyGuardIsCatalogBasedAndPermissiveOnly(t *testing.T) {
	ctx := context.Background()
	pool := ten02Setup(ctx, t)
	t.Cleanup(pool.Close)

	// Hermetic against a probe a prior crashed run may have left behind.
	mustExec(ctx, t, pool, `DROP TABLE IF EXISTS public.provider_policy_probe`)
	t.Cleanup(func() {
		mustExec(context.Background(), t, pool, `DROP TABLE IF EXISTS public.provider_policy_probe`)
	})

	if err := tenancy.AssertIsolationPosture(ctx, pool); err != nil {
		t.Fatalf("posture must pass on a freshly migrated DB: %v", err)
	}

	mustExec(ctx, t, pool, `CREATE TABLE public.provider_policy_probe (tenant_id uuid NOT NULL)`)
	mustExec(ctx, t, pool, `ALTER TABLE public.provider_policy_probe ENABLE ROW LEVEL SECURITY`)
	mustExec(ctx, t, pool, `ALTER TABLE public.provider_policy_probe FORCE ROW LEVEL SECURITY`)
	mustExec(ctx, t, pool, `CREATE POLICY prov_probe ON public.provider_policy_probe FOR SELECT TO probectl_provider USING (true)`)

	// Catalog-based: the guard must SEE the probe's unconstrained PERMISSIVE
	// provider read though probectl_app has no grant on the table (which is
	// exactly what information_schema would hide) and FATAL, naming the table.
	err := tenancy.AssertIsolationPosture(ctx, pool)
	if err == nil || !strings.Contains(err.Error(), "provider_policy_probe") {
		t.Fatalf("an unconstrained PERMISSIVE provider read must FATAL and name the table; got: %v", err)
	}

	// Permissive-only: a RESTRICTIVE USING(true) is a constraint, not a grant, so
	// posture must pass — nothing else fires on the probe.
	mustExec(ctx, t, pool, `DROP POLICY prov_probe ON public.provider_policy_probe`)
	mustExec(ctx, t, pool, `CREATE POLICY prov_probe ON public.provider_policy_probe AS RESTRICTIVE FOR SELECT TO probectl_provider USING (true)`)
	if err := tenancy.AssertIsolationPosture(ctx, pool); err != nil {
		t.Fatalf("a RESTRICTIVE provider policy must NOT be read as an unconstrained grant: %v", err)
	}
}
