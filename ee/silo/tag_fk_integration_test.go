// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package silo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// The migration login seeds the fixture; every assertion then runs as the
// serve role with a tenant GUC. A wrong kind/context/tenant must fail in the
// silo's own PostgreSQL constraints and FORCE-RLS policy.
func TestTagSiloStorageRejectsForeignKindContextAndTenant(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := context.Background()
	stamp := fmt.Sprintf("%d", time.Now().UnixNano())
	a := mkTenant(t, pool, "tag-silo-a-"+stamp, "siloed", "")
	b := mkTenant(t, pool, "tag-silo-b-"+stamp, "siloed", "")
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, tenant := range []string{a, b} {
		if err := prov.Provision(ctx, tenant, "", tenancy.IsolationSiloed); err != nil {
			t.Fatalf("provision tag silo: %v", err)
		}
	}
	t.Cleanup(func() {
		for _, tenant := range []string{a, b} {
			if err := prov.Teardown(context.Background(), tenant, "", tenancy.IsolationSiloed); err != nil {
				t.Errorf("teardown tag silo: %v", err)
			}
		}
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove tag fixture tenants: %v", err)
		}
	})
	schemaA, schemaB := quoteIdent(SchemaName(a)), quoteIdent(SchemaName(b))
	contextA, contextOther, contextB := uuid.NewString(), uuid.NewString(), uuid.NewString()
	seedContext := func(schema, tenant, routingContext string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.entity_contexts
			(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
			VALUES ($1,$2,$3,$4,$3::uuid::text,$4::uuid::text)`,
			tenant, routingContext, uuid.NewString(), uuid.NewString()); err != nil {
			t.Fatal(err)
		}
	}
	seedContext(schemaA, a, contextA)
	seedContext(schemaA, a, contextOther)
	seedContext(schemaB, b, contextB)
	entityID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entities
		(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'device','edge-a')`,
		a, contextA, entityID); err != nil {
		t.Fatal(err)
	}
	tagA, tagB := uuid.NewString(), uuid.NewString()
	appExec := func(caller, sql string, args ...any) error {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('probectl.tenant_id',$1,true)`, caller); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	for _, row := range []struct{ schema, tenant, id string }{
		{schemaA, a, tagA}, {schemaB, b, tagB},
	} {
		if err := appExec(row.tenant, `INSERT INTO `+row.schema+`.tenant_tag_definitions
			(tenant_id,id,key) VALUES ($1,$2,'customer')`, row.tenant, row.id); err != nil {
			t.Fatalf("own tag definition and revision trigger: %v", err)
		}
	}
	insert := `INSERT INTO ` + schemaA + `.tenant_tag_assignments
		(tenant_id,context_id,id,tag_id,target_kind,entity_id,entity_kind,value,source)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'customer-a','manual')`
	for _, tc := range []struct {
		name, tenant, routingContext, tagID, kind, entityKind string
		wantReject                                            bool
	}{
		{"own device", a, contextA, tagA, "device", "device", false},
		{"wrong entity kind", a, contextA, tagA, "interface", "interface", true},
		{"wrong routing context", a, contextOther, tagA, "device", "device", true},
		{"other tenant tag", a, contextA, tagB, "device", "device", true},
		{"other tenant caller", b, contextA, tagA, "device", "device", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := appExec(tc.tenant, insert, a, tc.routingContext,
				uuid.NewString(), tc.tagID, tc.kind, entityID, tc.entityKind)
			if tc.wantReject && err == nil {
				t.Fatal("PostgreSQL accepted an unowned or wrong-kind tag assignment")
			}
			if !tc.wantReject && err != nil {
				t.Fatalf("own assignment rejected: %v", err)
			}
		})
	}
	var revision int64
	if err := pool.QueryRow(ctx, `SELECT revision FROM `+schemaA+`.tenant_tag_revisions
		WHERE tenant_id=$1`, a).Scan(&revision); err != nil || revision <= 1 {
		t.Fatalf("accepted definition/assignment did not advance revision: %d, %v", revision, err)
	}
	// Simulate a silo created before FX-3. Its old path binding must be copied
	// into the new general test binding before the new composite FK is added.
	pathTestID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.tests
		(id,tenant_id,name,target) VALUES ($1,$2,'tag-path','10.42.0.1')`,
		pathTestID, a); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entity_path_test_contexts
		(tenant_id,test_id,context_id,path_target)
		VALUES ($1,$2,$3,'10.42.0.1')`, a, pathTestID, contextA); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"tenant_tag_assignments", "tenant_tag_rules", "tenant_tag_definitions",
		"tenant_tag_revisions", "entity_test_contexts",
	} {
		if _, err := pool.Exec(ctx, `DROP TABLE `+schemaA+`.`+quoteIdent(table)+` CASCADE`); err != nil {
			t.Fatalf("simulate pre-tag silo table %s: %v", table, err)
		}
	}
	for _, index := range []string{
		"entities_tenant_context_id_kind_uidx",
		"entity_sources_tenant_context_identity_uidx",
	} {
		if _, err := pool.Exec(ctx, `DROP INDEX `+schemaA+`.`+quoteIdent(index)); err != nil {
			t.Fatalf("simulate pre-tag silo index %s: %v", index, err)
		}
	}
	if err := prov.CatchUpSchema(ctx, a); err != nil {
		t.Fatalf("catch up pre-tag silo: %v", err)
	}
	if err := prov.CatchUpSchema(ctx, a); err != nil {
		t.Fatalf("second tag silo catch-up was not idempotent: %v", err)
	}
	var copied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+schemaA+`.entity_test_contexts
		WHERE tenant_id=$1 AND test_id=$2 AND context_id=$3`,
		a, pathTestID, contextA).Scan(&copied); err != nil || copied != 1 {
		t.Fatalf("old path context did not copy into general binding: %d, %v", copied, err)
	}
	postTag := uuid.NewString()
	if err := appExec(a, `INSERT INTO `+schemaA+`.tenant_tag_definitions
		(tenant_id,id,key) VALUES ($1,$2,'site')`, a, postTag); err != nil {
		t.Fatalf("caught-up revision trigger or definition FK failed: %v", err)
	}
	if err := appExec(a, insert, a, contextA, uuid.NewString(), postTag,
		"interface", entityID, "interface"); err == nil {
		t.Fatal("caught-up silo lost the entity-kind FK")
	}
	if _, err := pool.Exec(ctx, `UPDATE `+schemaA+`.tests SET target='10.42.0.2'
		WHERE tenant_id=$1 AND id=$2`, a, pathTestID); err != nil {
		t.Fatalf("retarget caught-up test: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+schemaA+`.entity_test_contexts
		WHERE tenant_id=$1 AND test_id=$2`, a, pathTestID).Scan(&copied); err != nil || copied != 0 {
		t.Fatalf("retarget kept a stale general context: %d, %v", copied, err)
	}
}

// A tag snapshot reads several tables. The first read must hold all silo
// tables against DROP, including a table the snapshot has not reached yet.
func TestTagSiloReadSnapshotBlocksDropBeforeLaterRead(t *testing.T) {
	ctx := context.Background()
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	tenantID := mkTenant(t, pool,
		fmt.Sprintf("tag-snapshot-lock-%d", time.Now().UnixNano()), "siloed", "")
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := prov.Provision(ctx, tenantID, "", tenancy.IsolationSiloed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := prov.Teardown(context.Background(), tenantID, "", tenancy.IsolationSiloed); err != nil {
			t.Errorf("teardown tag snapshot silo: %v", err)
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenantID); err != nil {
			t.Errorf("remove tag snapshot tenant: %v", err)
		}
	})
	previous := tenancy.CurrentRouter()
	t.Cleanup(func() {
		tenancy.SetRouter(previous)
		tenancy.SetSiloRequiredTables(nil)
	})
	tenancy.SetRouter(NewRouter(pool, nil, 0).WithQuarantine(tenancy.NewQuarantine()))
	required, err := RequiredSiloTables(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	tenancy.SetSiloRequiredTables(required)

	err = tenancy.InTenantReadSnapshot(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM tenant_tag_definitions`).Scan(&count); err != nil {
				return err
			}
			dropTx, err := pool.Begin(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = dropTx.Rollback(context.Background()) }()
			if _, err := dropTx.Exec(ctx, `SET LOCAL lock_timeout = '300ms'`); err != nil {
				return err
			}
			_, err = dropTx.Exec(ctx, `DROP TABLE `+quoteIdent(SchemaName(tenantID))+`.tenant_tag_rules CASCADE`)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
				t.Fatalf("DROP of unread silo tag table was not blocked by snapshot: %v", err)
			}
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM tenant_tag_rules`).Scan(&count)
		})
	if err != nil {
		t.Fatalf("silo tag snapshot failed after blocked DROP: %v", err)
	}
}
