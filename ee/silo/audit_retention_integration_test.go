// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package silo

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
)

// TestAuditRetentionRoutesSiloAndPooledSequenceAnchors proves the privileged
// delete leg and non-bypass receipt leg use the tenant's real PostgreSQL target.
// The same full-prune transition runs for one pooled and one siloed tenant;
// neither can touch or see the other's rows/head.
func TestAuditRetentionRoutesSiloAndPooledSequenceAnchors(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := context.Background()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	pooledID := mkTenant(t, pool, "audit-retention-pool-"+stamp, "pooled", "")
	siloedID := mkTenant(t, pool, "audit-retention-silo-"+stamp, "siloed", "")
	provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if err := provisioner.Provision(ctx, siloedID, "", tenancy.IsolationSiloed); err != nil {
		t.Fatalf("provision audit-retention silo: %v", err)
	}
	t.Cleanup(func() {
		if err := provisioner.Teardown(ctx, siloedID, "", tenancy.IsolationSiloed); err != nil {
			t.Errorf("cleanup audit-retention silo: %v", err)
		}
	})
	schema := SchemaName(siloedID)
	quotedSchema := pgx.Identifier{schema}.Sanitize()

	router := NewRouter(pool, nil, time.Second)
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(nil) })

	for _, tenantID := range []string{pooledID, siloedID} {
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			func(ctx context.Context, scope tenancy.Scope) error {
				for seq := 1; seq <= 3; seq++ {
					if _, err := audit.TenantAppend(
						ctx,
						scope,
						"silo-retention-test",
						"retention.seed",
						fmt.Sprintf("%s-%d", tenantID, seq),
						nil,
					); err != nil {
						return err
					}
				}
				return (store.SIEMDelivery{}).Advance(ctx, scope, 3)
			},
		)
		if err != nil {
			t.Fatalf("seed audit stream %s: %v", tenantID, err)
		}
	}

	// Put one deliberately misrouted sentinel for the *other* tenant in each
	// physical audit table. A handler predicate alone could delete these; the
	// provider-role/GUC boundary below must make both rows invisible to DELETE.
	const crossTenantSentinelSeq = int64(900000001)
	if _, err := pool.Exec(
		ctx,
		`INSERT INTO public.audit_events
		    (tenant_id, seq, actor, action, target, data, prev_hash, hash)
		 VALUES ($1::uuid, $2, 'isolation-test', 'sentinel', 'misrouted-public',
		         '{}'::jsonb, 'sentinel-prev', 'sentinel-hash')`,
		siloedID,
		crossTenantSentinelSeq,
	); err != nil {
		t.Fatalf("seed public cross-tenant audit sentinel: %v", err)
	}
	if _, err := pool.Exec(
		ctx,
		`INSERT INTO `+quotedSchema+`.audit_events
		    (tenant_id, seq, actor, action, target, data, prev_hash, hash)
		 VALUES ($1::uuid, $2, 'isolation-test', 'sentinel', 'misrouted-silo',
		         '{}'::jsonb, 'sentinel-prev', 'sentinel-hash')`,
		pooledID,
		crossTenantSentinelSeq,
	); err != nil {
		t.Fatalf("seed silo cross-tenant audit sentinel: %v", err)
	}

	for _, tc := range []struct {
		scoped string
		other  string
	}{
		{scoped: pooledID, other: siloedID},
		{scoped: siloedID, other: pooledID},
	} {
		err := tenancy.InTenantProviderMaintenance(
			tenancy.WithTenant(ctx, tenancy.ID(tc.scoped)),
			pool,
			func(ctx context.Context, scope tenancy.Scope) error {
				var role string
				if err := scope.Q.QueryRow(ctx, `SELECT current_user`).Scan(&role); err != nil {
					return err
				}
				if role != tenancy.ProviderRole {
					return fmt.Errorf(
						"tenant maintenance role = %q, want %q",
						role,
						tenancy.ProviderRole,
					)
				}

				var ownEvents, ownHeads int
				if err := scope.Q.QueryRow(
					ctx,
					`SELECT count(*) FROM audit_events WHERE tenant_id = $1::uuid`,
					tc.scoped,
				).Scan(&ownEvents); err != nil {
					return err
				}
				if err := scope.Q.QueryRow(
					ctx,
					`SELECT count(*)
					   FROM public.audit_stream_heads
					  WHERE tenant_id = $1::uuid`,
					tc.scoped,
				).Scan(&ownHeads); err != nil {
					return err
				}
				if ownEvents != 3 || ownHeads != 1 {
					return fmt.Errorf(
						"provider maintenance own scope events/heads = %d/%d, want 3/1",
						ownEvents,
						ownHeads,
					)
				}

				eventTag, err := scope.Q.Exec(
					ctx,
					`DELETE FROM audit_events WHERE tenant_id = $1::uuid`,
					tc.other,
				)
				if err != nil {
					return fmt.Errorf("cross-tenant audit delete probe: %w", err)
				}
				headTag, err := scope.Q.Exec(
					ctx,
					`UPDATE public.audit_stream_heads
					    SET updated_at = updated_at
					  WHERE tenant_id = $1::uuid`,
					tc.other,
				)
				if err != nil {
					return fmt.Errorf("cross-tenant audit head update probe: %w", err)
				}
				if eventTag.RowsAffected() != 0 || headTag.RowsAffected() != 0 {
					return fmt.Errorf(
						"cross-tenant maintenance mutated events/heads = %d/%d, want 0/0",
						eventTag.RowsAffected(),
						headTag.RowsAffected(),
					)
				}
				return nil
			},
		)
		if err != nil {
			t.Fatalf("prove provider maintenance boundary for %s: %v", tc.scoped, err)
		}
	}

	// The cross-tenant rows survived both provider-role mutation attempts.
	if got := countIn(t, pool, "public.audit_events", siloedID); got != 1 {
		t.Fatalf("public cross-tenant sentinel rows = %d, want 1", got)
	}
	if got := countIn(t, pool, schema+".audit_events", pooledID); got != 1 {
		t.Fatalf("silo cross-tenant sentinel rows = %d, want 1", got)
	}
	if _, err := pool.Exec(
		ctx,
		`DELETE FROM public.audit_events
		  WHERE tenant_id = $1::uuid AND seq = $2`,
		siloedID,
		crossTenantSentinelSeq,
	); err != nil {
		t.Fatalf("cleanup public cross-tenant sentinel: %v", err)
	}
	if _, err := pool.Exec(
		ctx,
		`DELETE FROM `+quotedSchema+`.audit_events
		  WHERE tenant_id = $1::uuid AND seq = $2`,
		pooledID,
		crossTenantSentinelSeq,
	); err != nil {
		t.Fatalf("cleanup silo cross-tenant sentinel: %v", err)
	}

	// Receipt insertion still runs as probectl_app, but that role must remain
	// physically unable to delete even its own append-only audit row.
	for _, tenantID := range []string{pooledID, siloedID} {
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			func(ctx context.Context, scope tenancy.Scope) error {
				_, err := scope.Q.Exec(
					ctx,
					`DELETE FROM audit_events WHERE tenant_id = $1::uuid AND seq = 1`,
					tenantID,
				)
				return err
			},
		)
		if err == nil {
			t.Fatalf("app role deleted append-only audit row for %s", tenantID)
		}
	}

	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.audit_events SET created_at = $1 WHERE tenant_id = $2::uuid`,
		old,
		pooledID,
	); err != nil {
		t.Fatalf("backdate pooled audit stream: %v", err)
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE `+quotedSchema+`.audit_events
		    SET created_at = $1
		  WHERE tenant_id = $2::uuid`,
		old,
		siloedID,
	); err != nil {
		t.Fatalf("backdate silo audit stream: %v", err)
	}

	policy := audit.RetentionPolicy{Window: 24 * time.Hour}
	for _, tenantID := range []string{pooledID, siloedID} {
		if pruned, err := audit.PruneTenant(
			ctx,
			pool,
			tenantID,
			policy,
			3,
			now,
		); err != nil || pruned != 3 {
			t.Fatalf("prune tenant %s = (%d, %v), want (3, nil)", tenantID, pruned, err)
		}
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			func(ctx context.Context, scope tenancy.Scope) error {
				ev, err := audit.TenantAppend(
					ctx,
					scope,
					"silo-retention-test",
					"retention.after",
					tenantID+"-after",
					nil,
				)
				if err != nil {
					return err
				}
				if ev.Seq != 5 {
					return fmt.Errorf("post-prune seq = %d, want 5", ev.Seq)
				}
				if err := audit.TenantVerify(ctx, scope); err != nil {
					return err
				}
				var ownHeads, otherHeads int
				if err := scope.Q.QueryRow(
					ctx,
					`SELECT count(*) FROM public.audit_stream_heads`,
				).Scan(&ownHeads); err != nil {
					return err
				}
				other := pooledID
				if tenantID == pooledID {
					other = siloedID
				}
				if err := scope.Q.QueryRow(
					ctx,
					`SELECT count(*)
					   FROM public.audit_stream_heads
					  WHERE tenant_id = $1::uuid`,
					other,
				).Scan(&otherHeads); err != nil {
					return err
				}
				if ownHeads != 1 || otherHeads != 0 {
					return fmt.Errorf(
						"audit head RLS = own/all:%d other:%d, want 1/0",
						ownHeads,
						otherHeads,
					)
				}
				return nil
			},
		)
		if err != nil {
			t.Fatalf("verify tenant %s after prune: %v", tenantID, err)
		}
	}

	if got := countIn(t, pool, "public.audit_events", siloedID); got != 0 {
		t.Fatalf("siloed audit rows leaked into pooled table: %d", got)
	}
	if got := countIn(t, pool, schema+".audit_events", siloedID); got != 2 {
		t.Fatalf("siloed receipt+append rows = %d, want 2", got)
	}
	if got := countIn(t, pool, "public.audit_events", pooledID); got != 2 {
		t.Fatalf("pooled receipt+append rows = %d, want 2", got)
	}
	if got := countIn(t, pool, schema+".audit_events", pooledID); got != 0 {
		t.Fatalf("pooled audit rows leaked into silo table: %d", got)
	}
}
