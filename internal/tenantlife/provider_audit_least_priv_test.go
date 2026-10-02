// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// AUD-04 (live Postgres): the provider role has NO direct read/mutate path to a
// tenant audit row. Before AUD-04 the provider held GUC-scoped SELECT + DELETE
// on audit_events, "authorized" by current_setting('probectl.tenant_id') — but
// any role can set that GUC itself, so it was caller-controlled input, not an
// authority. Now the provider holds no SELECT/DELETE grant at all: with ANY
// value of the tenant GUC (including one it sets itself) both operations fail
// permission-denied. Legitimate retention/erase runs through the SECURITY
// DEFINER functions, exercised by the retention and S-T5 suites.
func TestProviderCannotReadCrossTenantAudit(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()

	stamp := time.Now().UTC().Format("150405.000000")
	ta := mkTenant(t, pool, "it-paudit-a-"+stamp)
	tb := mkTenant(t, pool, "it-paudit-b-"+stamp)
	seedTenant(t, pool, ta, "a-probe") // seedTenant also writes one audit_events row
	seedTenant(t, pool, tb, "b-probe")

	denied := func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "42501"
	}

	// A provider SELECT of audit_events is refused at the grant layer for every
	// GUC the role might set — no GUC, a bystander tenant, or the target itself.
	// (The old contract returned 0 rows with no GUC and the target's rows when
	// the role set the target GUC; both are now hard permission denials.)
	for _, tc := range []struct {
		name string
		guc  string
	}{
		{name: "no GUC", guc: ""},
		{name: "GUC = other tenant B", guc: tb},
		{name: "GUC = target tenant A (the self-set attack)", guc: ta},
	} {
		err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
			if tc.guc != "" {
				if _, err := q.Exec(ctx, `SELECT set_config('probectl.tenant_id', $1, true)`, tc.guc); err != nil {
					return err
				}
			}
			var n int64
			return q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id = $1`, ta).Scan(&n)
		})
		if !denied(err) {
			t.Fatalf("provider SELECT audit_events (%s) = %v, want permission denied (42501)", tc.name, err)
		}
	}

	// A provider DELETE of audit_events is refused even when the role sets the
	// target tenant's GUC — the exact move the finding described (truncate the
	// tail of tenant A's chain).
	delErr := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		if _, err := q.Exec(ctx, `SELECT set_config('probectl.tenant_id', $1, true)`, ta); err != nil {
			return err
		}
		_, err := q.Exec(ctx, `DELETE FROM audit_events WHERE tenant_id = $1`, ta)
		return err
	})
	if !denied(delErr) {
		t.Fatalf("provider DELETE audit_events (GUC=A) = %v, want permission denied (42501)", delErr)
	}

	// Both tenants' seeded rows survive the refused provider mutations.
	for _, tid := range []string{ta, tb} {
		var n int64
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM audit_events WHERE tenant_id = $1::uuid`, tid).Scan(&n); err != nil {
			t.Fatalf("count audit rows for %s: %v", tid, err)
		}
		if n < 1 {
			t.Fatalf("tenant %s audit rows = %d, want >=1 (refused provider mutations must not delete)", tid, n)
		}
	}
}
