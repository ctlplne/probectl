// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife

import (
	"context"
	"encoding/hex"
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestPooledTenantEraseFlowQueryTablesWriteFence(t *testing.T) {
	admin := itPool(t)
	t.Cleanup(admin.Close)
	testsupport.LockPostgresPublicCatalog(t, admin)
	red := mkTenant(t, admin, "probectl-qa-beta-query-fence-red-"+flowQueryUUID(t))
	blue := mkTenant(t, admin, "probectl-qa-beta-query-fence-blue-"+flowQueryUUID(t))
	id := flowQueryUUID(t)
	hash := hex.EncodeToString(crypto.Hash([]byte("owned query fence fixture")))
	tables := []string{"flow_query_filters", "flow_query_views", "flow_query_view_preferences", "flow_snapshot_epochs", "flow_snapshots"}
	t.Cleanup(func() {
		ctx := context.Background()
		for _, table := range []string{"flow_query_view_preferences", "flow_query_views", "flow_query_filters", "flow_snapshots", "flow_snapshot_epochs"} {
			if _, err := admin.Exec(ctx, `DELETE FROM `+pgIdent(table)+` WHERE tenant_id=ANY($1::uuid[])`, []string{red, blue}); err != nil {
				t.Error(err)
			}
		}
		if _, err := admin.Exec(ctx, `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{red, blue}); err != nil {
			t.Error(err)
		}
	})
	statements := []struct {
		sql  string
		args func(string) []any
	}{
		{`INSERT INTO flow_query_filters(tenant_id,id,name,expression,version,updated_by,created_at,updated_at)VALUES($1::uuid,$2::uuid,'owned fence','{}',1,'owned',now(),now()) ON CONFLICT(tenant_id,id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id`, func(tenant string) []any { return []any{tenant, id} }},
		{`INSERT INTO flow_query_views(tenant_id,id,owner_id,name,visibility,definition,version,created_at,updated_at)VALUES($1::uuid,$2::uuid,'owned','owned fence','tenant','{"name":"owned fence","visibility":"tenant","plan":{},"time":{}}',1,now(),now()) ON CONFLICT(tenant_id,id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id`, func(tenant string) []any { return []any{tenant, id} }},
		{`INSERT INTO flow_query_view_preferences(tenant_id,owner_id,view_id,favorite)VALUES($1::uuid,'owned',$2::uuid,true) ON CONFLICT(tenant_id,owner_id,view_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id`, func(tenant string) []any { return []any{tenant, id} }},
		{`INSERT INTO flow_snapshot_epochs(tenant_id,generation,invalidating)VALUES($1::uuid,1,false) ON CONFLICT(tenant_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id`, func(tenant string) []any { return []any{tenant} }},
		{`INSERT INTO flow_snapshots(tenant_id,id,owner_id,generation,query_hash,object_lane,created_at,expires_at,row_count,page_size,permissions,private_header,charged_bytes,state)VALUES($1::uuid,$2::uuid,'owned',1,$3,'pooled',now(),now()+interval '1 hour',0,1,ARRAY['flow.read'],'owned private cache fixture',octet_length('owned private cache fixture'),'pending') ON CONFLICT(tenant_id,id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id`, func(tenant string) []any { return []any{tenant, id, hash} }},
	}
	for _, tenant := range []string{red, blue} {
		for _, statement := range statements {
			if _, err := admin.Exec(t.Context(), statement.sql, statement.args(tenant)...); err != nil {
				t.Fatal("owned new-table fence seed failed", err)
			}
		}
	}
	var guards int
	if err := admin.QueryRow(t.Context(), `SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_proc p ON p.oid=t.tgfoid WHERE n.nspname='public' AND c.relname=ANY($1::text[]) AND t.tgname='tenant_write_fence' AND NOT t.tgisinternal AND t.tgenabled='A' AND t.tgtype=23 AND p.proname='probectl_enforce_tenant_write_fence'`, tables).Scan(&guards); err != nil || guards != len(tables) {
		t.Fatal("new flow query table lacks exact ALWAYS INSERT/UPDATE storage fence", err, guards)
	}
	engine := New(admin, nil, nil, nil, nil, "owned fixture backups", testLog())
	if err := engine.fenceTenantAuditWrites(t.Context(), red, "privacy-admin"); err != nil {
		t.Fatal(err)
	}
	for index, table := range tables {
		// Even the migration/table-owner login cannot repopulate a fenced
		// tenant. The healthy sibling can still insert/upsert and update.
		for _, sql := range []struct {
			text string
			args []any
		}{{statements[index].sql, statements[index].args(red)}, {`UPDATE ` + pgIdent(table) + ` SET tenant_id=tenant_id WHERE tenant_id=$1::uuid`, []any{red}}} {
			_, err := admin.Exec(t.Context(), sql.text, sql.args...)
			var denied *pgconn.PgError
			if !errors.As(err, &denied) || denied.Code != "55000" {
				t.Fatal("new flow query table accepted a late fenced writer", table, err)
			}
		}
		if changed, err := admin.Exec(t.Context(), statements[index].sql, statements[index].args(blue)...); err != nil || changed.RowsAffected() != 1 {
			t.Fatal("red fence blocked healthy blue insert/upsert", table, err)
		}
		if changed, err := admin.Exec(t.Context(), `UPDATE `+pgIdent(table)+` SET tenant_id=tenant_id WHERE tenant_id=$1::uuid`, blue); err != nil || changed.RowsAffected() != 1 {
			t.Fatal("red fence blocked healthy blue update", table, err)
		}
	}
}

func TestPooledTenantEraseFlowQueryMigrationUpgradeWithFencedAdmin(t *testing.T) {
	admin := itPool(t)
	t.Cleanup(admin.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	database := "probectl_qa_beta_flow_upgrade_" + strings.ReplaceAll(flowQueryUUID(t), "-", "")
	quoted := pgx.Identifier{database}.Sanitize()
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+quoted); err != nil {
		t.Fatal("owned upgrade database creation failed", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, `DROP DATABASE `+quoted+` WITH (FORCE)`); err != nil {
			t.Error("owned upgrade database cleanup failed", err)
		} else {
			t.Log("owned nested migration upgrade database removed")
		}
	})
	config := admin.Config().Copy()
	config.ConnConfig.Database = database
	upgrade, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("owned upgrade pool unavailable")
	}
	t.Cleanup(upgrade.Close)
	testsupport.LockPostgresPublicCatalog(t, upgrade)
	older, through134 := fstest.MapFS{}, fstest.MapFS{}
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		version, err := strconv.Atoi(name[:4])
		if err != nil {
			t.Fatal(err)
		}
		if version <= 134 {
			body, err := fs.ReadFile(migrations.FS, name)
			if err != nil {
				t.Fatal(err)
			}
			through134[name] = &fstest.MapFile{Data: body}
			if version <= 131 {
				older[name] = &fstest.MapFile{Data: body}
			}
		}
	}
	if _, err := migrate.New(older, nil).Apply(ctx, upgrade); err != nil {
		t.Fatal("owned version131 deployment could not be prepared", err)
	}
	tenants := map[string]string{}
	for _, status := range []string{"active", "suspended", "offboarding"} {
		tenant := mkTenant(t, upgrade, "probectl-qa-beta-upgrade-"+status)
		tenants[status] = tenant
		var role string
		if err := upgrade.QueryRow(ctx, `INSERT INTO roles(tenant_id,slug,name,is_system)VALUES($1::uuid,'admin','Owned upgrade administrator',true)RETURNING id::text`, tenant).Scan(&role); err != nil {
			t.Fatal(err)
		}
		if _, err := upgrade.Exec(ctx, `INSERT INTO role_permissions(tenant_id,role_id,permission_key)VALUES($1::uuid,$2::uuid,'test.read')`, tenant, role); err != nil {
			t.Fatal(err)
		}
		if status == "suspended" {
			if _, err := upgrade.Exec(ctx, `UPDATE tenants SET status='suspended' WHERE id=$1::uuid`, tenant); err != nil {
				t.Fatal(err)
			}
		}
		if status == "offboarding" {
			engine := New(upgrade, nil, nil, nil, nil, "owned upgrade backups", testLog())
			if err := engine.fenceTenantAuditWrites(ctx, tenant, "privacy-admin"); err != nil {
				t.Fatal(err)
			}
		}
	}
	applied, err := migrate.New(through134, nil).Apply(ctx, upgrade)
	if err != nil {
		t.Fatal("flow query upgrade attempted to mutate a fenced administrator's grants", err)
	}
	if len(applied) != 3 || applied[0] != 132 || applied[1] != 133 || applied[2] != 134 {
		t.Fatal("owned upgrade did not apply exactly the three pending migrations", applied)
	}
	if again, err := migrate.New(through134, nil).Apply(ctx, upgrade); err != nil || len(again) != 0 {
		t.Fatal("restarted migration runner changed an already upgraded deployment", err)
	}
	// Replay the DDL/grant statements as well as the versioned runner. ON
	// CONFLICT cannot protect a fenced role from a BEFORE INSERT trigger.
	for _, name := range []string{"0132_flow_query_filters.sql", "0133_flow_snapshots.sql", "0134_flow_query_views.sql"} {
		body, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := upgrade.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("pending feature migration is not idempotent with a fenced tenant", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for status, tenant := range tenants {
		var granted, legacy int
		if err := upgrade.QueryRow(ctx, `SELECT count(*) FILTER(WHERE permission_key IN ('flow.filters.write','flow.views.write')),count(*) FILTER(WHERE permission_key='test.read') FROM role_permissions WHERE tenant_id=$1::uuid`, tenant).Scan(&granted, &legacy); err != nil {
			t.Fatal(err)
		}
		want := 2
		if status == "offboarding" {
			want = 0
		}
		if granted != want || legacy != 1 {
			t.Fatal("upgrade omitted eligible admin grants or changed fenced legacy grants", status, granted, legacy)
		}
		assertTenantStatus(ctx, t, upgrade, tenant, status)
	}
}
