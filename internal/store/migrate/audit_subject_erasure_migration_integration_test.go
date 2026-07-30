// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package migrate_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/migrations"
)

func TestAuditSubjectErasureMigrationBackfillsPooledAndSiloAsNonBypassOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := isolatedMigrationPool(ctx, t)
	if _, err := migrate.New(migrationsThrough(t, 76), nil).Apply(ctx, pool); err != nil {
		t.Fatalf("apply through 0076: %v", err)
	}

	const siloSchema = "t_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb"
	if _, err := pool.Exec(ctx, `
INSERT INTO tenants (id, slug, name, isolation_model) VALUES
  ($1, 'audit-subject-migration-a', 'Audit Subject Migration A', 'pooled'),
  ($2, 'audit-subject-migration-b', 'Audit Subject Migration B', 'siloed')
`, migrationTenantA, migrationTenantB); err != nil {
		t.Fatalf("seed pre-0077 tenants: %v", err)
	}
	if _, err := pool.Exec(ctx, `
CREATE SCHEMA `+siloSchema+`;
GRANT USAGE ON SCHEMA `+siloSchema+` TO probectl_app;
CREATE TABLE `+siloSchema+`.audit_events
  (LIKE public.audit_events INCLUDING ALL);
ALTER TABLE `+siloSchema+`.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE `+siloSchema+`.audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation
  ON `+siloSchema+`.audit_events
  USING (
      tenant_id =
      NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
  )
  WITH CHECK (
      tenant_id =
      NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
  );
`); err != nil {
		t.Fatalf("seed pre-0077 tenant routes: %v", err)
	}

	hashA := strings.Repeat("a", 64)
	hashB := strings.Repeat("b", 64)
	staleSiloHash := strings.Repeat("c", 64)
	if _, err := pool.Exec(ctx, `
INSERT INTO public.audit_events
  (tenant_id, seq, actor, action, target, data, prev_hash, hash)
VALUES
  ($1::uuid, 1, 'old-writer', 'privacy.subject_erase', 'pooled',
   jsonb_build_object('subject_hash', $3::text), '', 'pooled-event-hash'),
  ($2::uuid, 99, 'misrouted-old-writer', 'privacy.subject_erase', 'stale-public',
   jsonb_build_object('subject_hash', $4::text), '', 'stale-public-hash')
`, migrationTenantA, migrationTenantB, hashA, staleSiloHash); err != nil {
		t.Fatalf("seed pre-0077 pooled subject markers: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO `+siloSchema+`.audit_events
  (tenant_id, seq, actor, action, target, data, prev_hash, hash)
VALUES
  ($1::uuid, 1, 'old-writer', 'privacy.subject_erase', 'silo',
   jsonb_build_object('subject_hash', $2::text), '', 'silo-event-hash')
`, migrationTenantB, hashB); err != nil {
		t.Fatalf("seed pre-0077 silo subject marker: %v", err)
	}

	// This helper assumes a fresh NOSUPERUSER/NOBYPASSRLS migration owner and
	// transfers only the schema objects needed by 0075/0077. The owner is not
	// made a member of probectl_app or probectl_provider.
	ownerPool := auditHeadMigrationOwnerPool(ctx, t, pool)
	if _, err := migrate.New(migrationsThrough(t, 77), nil).Apply(ctx, ownerPool); err != nil {
		t.Fatalf("apply 0077 as non-bypass migration owner: %v", err)
	}

	// Direct replay proves the SQL body itself is idempotent, not merely hidden
	// behind the schema_migrations ledger.
	body, err := fs.ReadFile(migrations.FS, "0077_audit_subject_erasures.sql")
	if err != nil {
		t.Fatalf("read 0077 for replay: %v", err)
	}
	conn, err := ownerPool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire non-bypass owner for replay: %v", err)
	}
	if err := conn.Conn().PgConn().Exec(ctx, string(body)).Close(); err != nil {
		conn.Release()
		t.Fatalf("replay 0077 under FORCE RLS as non-bypass owner: %v", err)
	}
	conn.Release()

	assertProjectionCount(t, pool, "public.audit_subject_erasures", migrationTenantA, hashA, 1)
	assertProjectionCount(t, pool, "public.audit_subject_erasures", migrationTenantB, staleSiloHash, 0)
	assertProjectionCount(t, pool, siloSchema+".audit_subject_erasures", migrationTenantB, hashB, 1)
	assertProjectionCount(t, pool, siloSchema+".audit_subject_erasures", migrationTenantA, hashA, 0)

	var temporaryPolicies int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM pg_policies
		  WHERE policyname LIKE 'audit_subject_erasure_migration_%'`,
	).Scan(&temporaryPolicies); err != nil {
		t.Fatalf("inspect temporary migration policy: %v", err)
	}
	if temporaryPolicies != 0 {
		t.Fatalf("temporary migration policies remaining = %d, want 0", temporaryPolicies)
	}

	for _, table := range []string{
		"public.audit_subject_erasures",
		siloSchema + ".audit_subject_erasures",
	} {
		var enabled, forced bool
		if err := pool.QueryRow(
			ctx,
			`SELECT c.relrowsecurity, c.relforcerowsecurity
			   FROM pg_class AS c
			   JOIN pg_namespace AS n ON n.oid = c.relnamespace
			  WHERE n.nspname || '.' || c.relname = $1`,
			table,
		).Scan(&enabled, &forced); err != nil {
			t.Fatalf("inspect RLS flags for %s: %v", table, err)
		}
		if !enabled || !forced {
			t.Fatalf("%s RLS enabled/forced = %t/%t, want true/true", table, enabled, forced)
		}
	}

	assertProjectionRuntimeRLS(
		t,
		pool,
		"public",
		migrationTenantA,
		migrationTenantB,
	)
	assertProjectionRuntimeRLS(
		t,
		pool,
		siloSchema,
		migrationTenantB,
		migrationTenantA,
	)

	var restrictive, usingExpr, checkExpr string
	if err := pool.QueryRow(
		ctx,
		`SELECT permissive, qual, with_check
		   FROM pg_policies
		  WHERE schemaname = $1
		    AND tablename = 'audit_subject_erasures'
		    AND policyname = 'tenant_schema_isolation'`,
		siloSchema,
	).Scan(&restrictive, &usingExpr, &checkExpr); err != nil {
		t.Fatalf("inspect silo projection schema fence: %v", err)
	}
	if restrictive != "RESTRICTIVE" ||
		!strings.Contains(usingExpr, migrationTenantB) ||
		!strings.Contains(checkExpr, migrationTenantB) {
		t.Fatalf(
			"silo projection fence permissive/using/check = %q/%q/%q",
			restrictive,
			usingExpr,
			checkExpr,
		)
	}

	// Even a later permissive policy must not OR-bypass the restrictive schema
	// fence. Seed a deliberately misrouted tenant-A row in tenant B's physical
	// table as the test superuser, then prove tenant A cannot qualified-read it
	// or insert another A row into that table.
	misroutedHash := strings.Repeat("d", 64)
	if _, err := pool.Exec(
		ctx,
		`INSERT INTO `+siloSchema+`.audit_subject_erasures
		    (tenant_id, subject_hash)
		 VALUES ($1::uuid, $2)`,
		migrationTenantA,
		misroutedHash,
	); err != nil {
		t.Fatalf("seed misrouted projection fence sentinel: %v", err)
	}
	if _, err := pool.Exec(ctx, `
DROP POLICY IF EXISTS test_permissive_projection_bypass
    ON `+siloSchema+`.audit_subject_erasures;
CREATE POLICY test_permissive_projection_bypass
    ON `+siloSchema+`.audit_subject_erasures
    AS PERMISSIVE
    FOR ALL
    USING (true)
    WITH CHECK (true);
`); err != nil {
		t.Fatalf("install permissive projection bypass probe: %v", err)
	}
	assertSiloProjectionSchemaFence(
		t,
		pool,
		siloSchema,
		migrationTenantA,
		misroutedHash,
	)

	var (
		appSelect, appInsert, appUpdate, appDelete                     bool
		providerSelect, providerInsert, providerUpdate, providerDelete bool
	)
	if err := pool.QueryRow(ctx, `
SELECT has_table_privilege('probectl_app', 'public.audit_subject_erasures', 'SELECT'),
       has_table_privilege('probectl_app', 'public.audit_subject_erasures', 'INSERT'),
       has_table_privilege('probectl_app', 'public.audit_subject_erasures', 'UPDATE'),
       has_table_privilege('probectl_app', 'public.audit_subject_erasures', 'DELETE'),
       has_table_privilege('probectl_provider', 'public.audit_subject_erasures', 'SELECT'),
       has_table_privilege('probectl_provider', 'public.audit_subject_erasures', 'INSERT'),
       has_table_privilege('probectl_provider', 'public.audit_subject_erasures', 'UPDATE'),
       has_table_privilege('probectl_provider', 'public.audit_subject_erasures', 'DELETE')
`).Scan(
		&appSelect,
		&appInsert,
		&appUpdate,
		&appDelete,
		&providerSelect,
		&providerInsert,
		&providerUpdate,
		&providerDelete,
	); err != nil {
		t.Fatalf("inspect projection table privileges: %v", err)
	}
	if !appSelect || !appInsert || appUpdate || appDelete ||
		!providerSelect || !providerInsert || providerUpdate || !providerDelete {
		t.Fatalf(
			"projection privileges app(S/I/U/D)=%t/%t/%t/%t provider=%t/%t/%t/%t",
			appSelect,
			appInsert,
			appUpdate,
			appDelete,
			providerSelect,
			providerInsert,
			providerUpdate,
			providerDelete,
		)
	}
}

func assertProjectionCount(
	t *testing.T,
	pool *pgxpool.Pool,
	table, tenantID, hash string,
	want int,
) {
	t.Helper()
	var got int
	if err := pool.QueryRow(
		context.Background(),
		`SELECT count(*) FROM `+table+`
		  WHERE tenant_id = $1::uuid AND subject_hash = $2`,
		tenantID,
		hash,
	).Scan(&got); err != nil {
		t.Fatalf("count %s projection for %s: %v", table, tenantID, err)
	}
	if got != want {
		t.Fatalf(
			"%s projection count for %s/%s = %d, want %d",
			table,
			tenantID,
			hash[:8],
			got,
			want,
		)
	}
}

func assertProjectionRuntimeRLS(
	t *testing.T,
	pool *pgxpool.Pool,
	schema, ownTenant, otherTenant string,
) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin runtime RLS probe for %s: %v", schema, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err != nil {
		t.Fatalf("assume app role for %s: %v", schema, err)
	}
	if _, err := tx.Exec(
		ctx,
		`SELECT set_config('probectl.tenant_id', $1, true)`,
		ownTenant,
	); err != nil {
		t.Fatalf("bind tenant GUC for %s: %v", schema, err)
	}
	if _, err := tx.Exec(
		ctx,
		"SET LOCAL search_path TO "+quoteIdent(schema)+", public",
	); err != nil {
		t.Fatalf("route RLS probe for %s: %v", schema, err)
	}
	var own, other int
	if err := tx.QueryRow(
		ctx,
		`SELECT count(*) FROM audit_subject_erasures`,
	).Scan(&own); err != nil {
		t.Fatalf("read own projections through %s: %v", schema, err)
	}
	if err := tx.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM audit_subject_erasures
		  WHERE tenant_id = $1::uuid`,
		otherTenant,
	).Scan(&other); err != nil {
		t.Fatalf("probe foreign projection through %s: %v", schema, err)
	}
	if own != 1 || other != 0 {
		t.Fatalf(
			"%s projection RLS own/all=%d other=%d, want 1/0",
			schema,
			own,
			other,
		)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback runtime RLS probe for %s: %v", schema, err)
	}
}

func assertSiloProjectionSchemaFence(
	t *testing.T,
	pool *pgxpool.Pool,
	schema, qualifiedTenant, sentinelHash string,
) {
	t.Helper()
	ctx := context.Background()
	beginAppScope := func() pgx.Tx {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin silo projection fence probe: %v", err)
		}
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("assume app role for silo projection fence: %v", err)
		}
		if _, err := tx.Exec(
			ctx,
			`SELECT set_config('probectl.tenant_id', $1, true)`,
			qualifiedTenant,
		); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("bind tenant GUC for silo projection fence: %v", err)
		}
		return tx
	}

	readTx := beginAppScope()
	var visible int
	if err := readTx.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM `+quoteIdent(schema)+`.audit_subject_erasures
		  WHERE tenant_id = $1::uuid
		    AND subject_hash = $2`,
		qualifiedTenant,
		sentinelHash,
	).Scan(&visible); err != nil {
		_ = readTx.Rollback(ctx)
		t.Fatalf("qualified-read silo projection sentinel: %v", err)
	}
	if visible != 0 {
		_ = readTx.Rollback(ctx)
		t.Fatalf("qualified-read exposed %d cross-schema projection rows, want 0", visible)
	}
	if err := readTx.Rollback(ctx); err != nil {
		t.Fatalf("rollback qualified-read fence probe: %v", err)
	}

	insertHash := strings.Repeat("e", 64)
	insertTx := beginAppScope()
	_, insertErr := insertTx.Exec(
		ctx,
		`INSERT INTO `+quoteIdent(schema)+`.audit_subject_erasures
		    (tenant_id, subject_hash)
		 VALUES ($1::uuid, $2)`,
		qualifiedTenant,
		insertHash,
	)
	_ = insertTx.Rollback(ctx)
	if insertErr == nil {
		t.Fatal("qualified insert crossed the immutable silo projection fence")
	}

	assertProjectionCount(
		t,
		pool,
		schema+".audit_subject_erasures",
		qualifiedTenant,
		insertHash,
		0,
	)
}
