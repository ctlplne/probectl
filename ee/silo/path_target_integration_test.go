// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration || isolation

package silo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestSharedPathTargetsKeepSiloContextOnProvisionAndCatchup(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	// Prove the entire additive migration can replay against accepted rows;
	// the versioned runner has already applied it once on a fresh database.
	migration, err := migrations.FS.ReadFile("0200_path_target_context_membership.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(migration)); err != nil {
		t.Fatal("idempotent path target migration", err)
	}
	tenants := []string{
		mkTenant(t, pool, fmt.Sprintf("path-shared-a-%d", time.Now().UnixNano()), "siloed", ""),
		mkTenant(t, pool, fmt.Sprintf("path-shared-b-%d", time.Now().UnixNano()), "siloed", ""),
	}
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() {
		for _, tenant := range tenants {
			if err := prov.Teardown(context.Background(), tenant, "", tenancy.IsolationSiloed); err != nil {
				t.Error(err)
			}
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	contexts := []string{uuid.NewString(), uuid.NewString()}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range tenants {
		if err := prov.Provision(ctx, tenant, "", tenancy.IsolationSiloed); err != nil {
			t.Fatal(err)
		}
		schema := quoteIdent(SchemaName(tenant))
		for _, area := range contexts {
			exec(`INSERT INTO `+schema+`.entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,$3::uuid::text,$4::uuid::text)`, tenant, area, uuid.NewString(), uuid.NewString())
		}
		ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
		for i, id := range ids {
			exec(`INSERT INTO `+schema+`.tests(tenant_id,id,name,type,target) VALUES($1,$2,$2::uuid::text,'icmp','192.0.2.1')`, tenant, id)
			area := contexts[0]
			if i == 2 {
				area = contexts[1]
			}
			exec(`INSERT INTO `+schema+`.entity_test_contexts(tenant_id,test_id,context_id) VALUES($1,$2,$3)`, tenant, id, area)
		}
		insert := `INSERT INTO ` + schema + `.entity_path_test_contexts(tenant_id,test_id,context_id,path_target) VALUES($1,$2,$3,'192.0.2.1')`
		exec(insert, tenant, ids[0], contexts[0])
		var assigned time.Time
		if err := pool.QueryRow(ctx, `SELECT assigned_at FROM `+schema+`.entity_path_test_contexts WHERE tenant_id=$1 AND test_id=$2`, tenant, ids[0]).Scan(&assigned); err != nil {
			t.Fatal(err)
		}
		if lane == 0 {
			// A pre-upgrade silo has its existing accepted binding but no shared
			// target anchor. Catch-up must backfill without changing its clock.
			exec(`DROP TRIGGER entity_path_target_context_guard ON ` + schema + `.entity_path_test_contexts`)
			exec(`DROP TRIGGER entity_path_target_context_cleanup ON ` + schema + `.entity_path_test_contexts`)
			exec(`ALTER TABLE ` + schema + `.entity_path_test_contexts DROP CONSTRAINT entity_path_test_target_context_fk`)
			exec(`DROP TABLE ` + schema + `.entity_path_targets`)
			exec(`ALTER TABLE ` + schema + `.entity_path_test_contexts ADD CONSTRAINT entity_path_target_one_context UNIQUE(tenant_id,path_target)`)
			for range 2 {
				if err := prov.CatchUpSchema(ctx, tenant); err != nil {
					t.Fatal(err)
				}
			}
		}
		var indexed bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_index idx
			WHERE idx.indrelid=($1||'.entity_path_test_contexts')::regclass
			AND idx.indisvalid AND idx.indisready AND NOT idx.indisunique
			AND idx.indpred IS NULL AND idx.indexprs IS NULL AND idx.indnkeyatts>=2
			AND pg_get_indexdef(idx.indexrelid,1,true)='tenant_id'
			AND pg_get_indexdef(idx.indexrelid,2,true)='path_target')`, SchemaName(tenant)).Scan(&indexed); err != nil || !indexed {
			t.Fatal("target references lost their lookup and cleanup index", indexed, err)
		}
		var current time.Time
		if err := pool.QueryRow(ctx, `SELECT assigned_at FROM `+schema+`.entity_path_test_contexts WHERE tenant_id=$1 AND test_id=$2`, tenant, ids[0]).Scan(&current); err != nil || !current.Equal(assigned) {
			t.Fatal("catch-up changed original binding time", assigned, current, err)
		}
		exec(insert, tenant, ids[1], contexts[0])
		_, err := pool.Exec(ctx, insert, tenant, ids[2], contexts[1])
		var constraint *pgconn.PgError
		if !errors.As(err, &constraint) || constraint.Code != "23505" || constraint.ConstraintName != "entity_path_target_one_context" {
			t.Fatal("silo admitted two contexts for one destination", err)
		}
		// Even the migration role cannot write a sibling tenant into this
		// private target relation; the literal-tenant CHECK is independent of RLS.
		_, err = pool.Exec(ctx, `INSERT INTO `+schema+`.entity_path_targets(tenant_id,path_target,context_id) VALUES($1,'192.0.2.99',$2)`, tenants[1-lane], contexts[0])
		if !errors.As(err, &constraint) || constraint.Code != "23514" {
			t.Fatal("private target relation accepted foreign tenant", err)
		}
		// Read the new relation through the actual serve role, including an
		// explicitly qualified foreign schema which search_path cannot protect.
		for _, caller := range tenants {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err == nil {
				_, err = tx.Exec(ctx, `SELECT set_config('probectl.tenant_id',$1,true)`, caller)
			}
			var count int
			if err == nil {
				err = tx.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.entity_path_targets`).Scan(&count)
			}
			_ = tx.Rollback(ctx)
			want := 0
			if caller == tenant {
				want = 1
			}
			if err != nil || count != want {
				t.Fatal("target relation FORCE-RLS or grants failed", caller, count, want, err)
			}
		}
		exec(`DELETE FROM `+schema+`.tests WHERE tenant_id=$1 AND id=ANY($2::uuid[])`, tenant, ids[:2])
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.entity_path_targets WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 0 {
			t.Fatal("last silo test deletion left an anchor", count, err)
		}
	}
	t.Log("real-integration: fresh and pre-anchor silo catch-up, original clock, shared destination context guard, qualified app-role RLS, literal-tenant CHECK and cleanup; no physical sender claim")
}
