// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package tenantlife

import (
	"context"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// TENANT-005 (live Postgres): the provider role must NOT be able to SELECT
// another tenant's tamper-evident audit log outside the scoped erase path.
// After 0045 the provider's audit_events SELECT policy is GUC-scoped exactly
// like the app-role policy: with no probectl.tenant_id set it reads NOTHING
// (fail closed), and with one tenant's GUC it can never see another tenant's
// rows. The DELETE capability (USING true + explicit WHERE) still functions so
// the erase engine works.
func TestProviderCannotReadCrossTenantAudit(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()

	stamp := time.Now().UTC().Format("150405.000000")
	ta := mkTenant(t, pool, "it-paudit-a-"+stamp)
	tb := mkTenant(t, pool, "it-paudit-b-"+stamp)
	seedTenant(t, pool, ta, "a-probe") // seedTenant also writes one audit_events row
	seedTenant(t, pool, tb, "b-probe")

	count := func(guc, tenant string) int64 {
		t.Helper()
		var n int64
		if err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
			if guc != "" {
				if _, err := q.Exec(ctx, `SELECT set_config('probectl.tenant_id', $1, true)`, guc); err != nil {
					return err
				}
			}
			return q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id = $1`, tenant).Scan(&n)
		}); err != nil {
			t.Fatalf("provider count (guc=%q tenant=%q): %v", guc, tenant, err)
		}
		return n
	}

	// 1) No GUC: the scoped SELECT policy returns NOTHING (fail closed).
	if n := count("", ta); n != 0 {
		t.Fatalf("provider with NO GUC read %d of tenant A's audit rows, want 0 (fail closed)", n)
	}
	// 2) GUC = tenant B: the provider cannot see tenant A's rows (the
	//    cross-tenant read the old FOR ALL USING(true) policy allowed).
	if n := count(tb, ta); n != 0 {
		t.Fatalf("provider scoped to B read %d of tenant A's audit rows, want 0 (CROSS-TENANT LEAK)", n)
	}
	// 3) GUC = tenant A: the scoped erase-verify read works (>=1 seeded row).
	if n := count(ta, ta); n < 1 {
		t.Fatalf("provider scoped to A read %d of A's own audit rows, want >=1 (erase-verify must still work)", n)
	}

	// 4) The DELETE capability still functions, exactly as the production erase
	//    drives it: the provider sets the tenant GUC, then DELETEs by explicit
	//    WHERE. The GUC matters — after 0045 the provider's SELECT policy is
	//    GUC-scoped, and a `DELETE ... WHERE` must READ the rows to match them,
	//    so with no GUC the rows are invisible and nothing is deleted. The real
	//    erase (tenantlife.go) sets probectl.tenant_id in the same provider tx;
	//    mirror that here. Erasing tenant A's chain leaves zero, B untouched.
	if err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		if _, err := q.Exec(ctx, `SELECT set_config('probectl.tenant_id', $1, true)`, ta); err != nil {
			return err
		}
		_, err := q.Exec(ctx, `DELETE FROM audit_events WHERE tenant_id = $1`, ta)
		return err
	}); err != nil {
		t.Fatalf("provider DELETE audit_events: %v", err)
	}
	if n := count(ta, ta); n != 0 {
		t.Fatalf("tenant A audit rows remain after provider DELETE: %d", n)
	}
	if n := count(tb, tb); n < 1 {
		t.Fatalf("tenant B audit rows damaged by A's erase: %d", n)
	}
}
