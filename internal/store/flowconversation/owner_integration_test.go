// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowconversation

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func ownerFixtureRuntime(ctx context.Context, t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	config := admin.Config().Copy()
	if dsn := os.Getenv("PROBECTL_WORKER_CREDENTIAL_TEST_DATABASE_URL"); dsn != "" {
		var err error
		config, err = pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal("owner runtime PostgreSQL configuration unavailable")
		}
	} else {
		entropy, err := crypto.Random(32)
		if err != nil {
			t.Fatal(err)
		}
		name := "probectl-qa-beta-owner-" + hex.EncodeToString(entropy[:8])
		password, err := crypto.Random(32)
		if err != nil {
			t.Fatal(err)
		}
		config.ConnConfig.User, config.ConnConfig.Password = name, hex.EncodeToString(password)
		clear(password)
		role := pgx.Identifier{name}.Sanitize()
		if _, err := admin.Exec(ctx, `CREATE ROLE `+role+` LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB PASSWORD '`+config.ConnConfig.Password+`'`); err != nil {
			t.Fatal("owned runtime role could not be created")
		}
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := admin.Exec(cleanup, `DROP ROLE `+role); err != nil {
				t.Error("owned runtime role cleanup failed")
			}
		})
		for _, statement := range []string{`GRANT probectl_app TO ` + role, `GRANT probectl_provider TO ` + role + ` WITH INHERIT FALSE, SET TRUE`} {
			if _, err := admin.Exec(ctx, statement); err != nil {
				t.Fatal("owned runtime role membership unavailable")
			}
		}
	}
	config.MaxConns = 1 // Every transaction below reuses the same real connection.
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("owner runtime PostgreSQL pool unavailable")
	}
	t.Cleanup(pool.Close)
	var super, bypass bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&super, &bypass); err != nil || super || bypass {
		t.Fatal("owner proof requires NOSUPERUSER NOBYPASSRLS login")
	}
	return pool
}

func TestHistoryOwnerPostgresRestrictiveBoundaryAndPrivateLifecycleReset(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, testsupport.PostgresDSN())
	if err != nil {
		t.Fatal("owner fixture PostgreSQL configuration unavailable")
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "owner fixture PostgreSQL unavailable")
		return
	}
	testsupport.LockPostgresPublicCatalog(t, admin)
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, admin); err != nil {
		t.Fatal(err)
	}
	pool := ownerFixtureRuntime(ctx, t, admin)
	var tls bool
	if err := pool.QueryRow(ctx, `SELECT COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),false)`).Scan(&tls); err != nil {
		t.Fatal(err)
	}
	if tls {
		t.Log("history owner runtime TLS transport verified")
	} else {
		t.Log("owner proof uses plaintext CI fixture; not TLS proof")
	}
	ids := make([]string, 5)
	for i := range ids {
		ids[i], err = crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
	}
	red, blue, first, second := ids[0], ids[1], ids[2], ids[3]
	schemaName := "probectl-qa-beta-owner-" + strings.ReplaceAll(ids[4], "-", "")
	schema := pgx.Identifier{schemaName}.Sanitize()
	table := schema + `."flow_conversation_messages"`
	// This is a disposable owner-policy fixture, not a new product source table.
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Error("owned owner-policy fixture cleanup failed")
		}
	})
	for _, statement := range []string{
		`GRANT USAGE ON SCHEMA ` + schema + ` TO probectl_app,probectl_provider`,
		`CREATE TABLE ` + table + ` (tenant_id uuid NOT NULL,owner_id uuid NOT NULL,body text NOT NULL)`,
		`ALTER TABLE ` + table + ` ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE ` + table + ` FORCE ROW LEVEL SECURITY`,
		`GRANT SELECT,INSERT,UPDATE,DELETE ON ` + table + ` TO probectl_app`,
		`CREATE POLICY legacy_open ON ` + table + ` USING(true) WITH CHECK(true)`,
		`CREATE POLICY flow_history_owner ON ` + table + ` AS RESTRICTIVE FOR ALL TO PUBLIC USING(` + tenancy.FlowHistoryOwnerPredicate + `) WITH CHECK(` + tenancy.FlowHistoryOwnerPredicate + `)`,
	} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `INSERT INTO `+table+` VALUES($1,$2,'red-first'),($1,$3,'red-second'),($4,$2,'blue-first')`, red, first, second, blue); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.AssertFlowHistoryOwnerGuard(ctx, pool, schemaName, "flow_conversation_messages"); err != nil {
		var expression string
		_ = admin.QueryRow(ctx, `SELECT qual FROM pg_policies WHERE schemaname=$1 AND tablename='flow_conversation_messages' AND policyname='flow_history_owner'`, schemaName).Scan(&expression)
		t.Fatalf("exact compiled owner predicate refused: %v; expression=%q", err, expression)
	}
	count := func(ctx context.Context, q tenancy.Querier) int {
		t.Helper()
		var n int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, tenant := range []string{red, blue} {
		scoped := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		if err := tenancy.InTenant(scoped, pool, func(ctx context.Context, sc tenancy.Scope) error {
			if count(ctx, sc.Q) != 0 {
				t.Fatal("missing owner GUC exposed private source")
			}
			if err := bindOwner(ctx, sc, first); err != nil {
				return err
			}
			if count(ctx, sc.Q) != 1 {
				t.Fatal("permissive policy bypassed tenant/owner boundary")
			}
			var label string
			if err := sc.Q.QueryRow(ctx, `SELECT body FROM `+table).Scan(&label); err != nil || !strings.HasPrefix(label, map[string]string{red: "red-", blue: "blue-"}[tenant]) {
				t.Fatal("owner query selected sibling tenant", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	scoped := tenancy.WithTenant(ctx, tenancy.ID(red))
	if err := tenancy.InTenant(scoped, pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := bindOwner(context.Background(), sc, first); !errors.Is(err, ErrMessageIntegrity) {
			t.Fatal("missing context reached owner binding", err)
		}
		if err := bindOwner(ctx, sc, "not-an-owner-uuid"); !errors.Is(err, ErrMessageIntegrity) {
			t.Fatal("invalid owner reached SQL binding", err)
		}
		if count(ctx, sc.Q) != 0 {
			t.Fatal("refused owner binding changed transaction scope")
		}
		if err := bindOwner(ctx, sc, first); err != nil {
			return err
		}
		if tag, err := sc.Q.Exec(ctx, `INSERT INTO `+table+` VALUES($1,$2,'own-write')`, red, first); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("valid own insert did not exercise granted write access", err)
		}
		if tag, err := sc.Q.Exec(ctx, `DELETE FROM `+table+` WHERE body='own-write'`); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("valid own delete failed", err)
		}
		if tag, err := sc.Q.Exec(ctx, `UPDATE `+table+` SET body='foreign-update' WHERE owner_id=$1::uuid`, second); err != nil || tag.RowsAffected() != 0 {
			t.Fatal("USING allowed mutation of a foreign owner", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, values := range [][2]string{{red, second}, {blue, first}} {
		err := tenancy.InTenant(scoped, pool, func(ctx context.Context, sc tenancy.Scope) error {
			if err := bindOwner(ctx, sc, first); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO `+table+` VALUES($1,$2,'spoof')`, values[0], values[1])
			return err
		})
		var denied *pgconn.PgError
		if !errors.As(err, &denied) || denied.Code != "42501" {
			t.Fatal("owner/tenant INSERT spoof did not fail at WITH CHECK", err)
		}
	}
	err = tenancy.InTenant(scoped, pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := bindOwner(ctx, sc, first); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `UPDATE `+table+` SET owner_id=$1::uuid`, second)
		return err
	})
	var updateDenied *pgconn.PgError
	if !errors.As(err, &updateDenied) || updateDenied.Code != "42501" {
		t.Fatal("UPDATE WITH CHECK allowed owner reassignment", err)
	}
	if err := tenancy.InTenant(scoped, pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := bindLifecycle(ctx, sc); err != nil {
			return err
		}
		if count(ctx, sc.Q) != 2 {
			t.Fatal("explicit maintenance did not remain tenant-scoped")
		}
		if err := bindOwner(ctx, sc, first); err != nil {
			return err
		}
		if count(ctx, sc.Q) != 1 {
			t.Fatal("owner binding inherited lifecycle access")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var outside int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&outside); err != nil || outside != 0 {
		t.Fatal("connection reuse retained owner/tenant/lifecycle GUC", err)
	}
	providerEntered := false
	err = tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		var role string
		if err := q.QueryRow(ctx, `SELECT current_user`).Scan(&role); err != nil || role != tenancy.ProviderRole {
			t.Fatal("provider proof did not assume the restricted role", err)
		}
		providerEntered = true
		var n int
		return q.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n)
	})
	var denied *pgconn.PgError
	if !providerEntered || !errors.As(err, &denied) || denied.Code != "42501" {
		t.Fatal("provider role acquired private source access or fixture failed", err)
	}
	if err := tenancy.InTenant(scoped, pool, func(ctx context.Context, sc tenancy.Scope) error {
		return tenancy.AssertPostureTx(ctx, sc.Q)
	}); err != nil {
		t.Fatal("complete startup posture rejected the exact owner guard", err)
	}
	testHistoryOwnerPostureTamper(ctx, t, admin, pool, schemaName, table)
}

func testHistoryOwnerPostureTamper(ctx context.Context, t *testing.T, admin, runtime *pgxpool.Pool, schema, table string) {
	t.Helper()
	plan := tenancy.FlowHistoryOwnerBoundaryPlan(schema, "flow_conversation_messages")
	regrouped := `(tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
        AND owner_id = NULLIF(current_setting('probectl.flow_history_owner', true), '')::uuid)
        OR current_setting('probectl.flow_history_lifecycle', true) = 'authorized'`
	policies := []string{
		"",
		strings.Replace(plan[1], " AS RESTRICTIVE", " AS PERMISSIVE", 1),
		strings.Replace(plan[1], "TO PUBLIC", "TO probectl_provider", 1),
		`CREATE POLICY flow_history_owner ON ` + table + ` AS RESTRICTIVE FOR SELECT TO PUBLIC USING (` + tenancy.FlowHistoryOwnerPredicate + `)`,
		`CREATE POLICY flow_history_owner ON ` + table + ` AS RESTRICTIVE FOR ALL TO PUBLIC USING (` + tenancy.FlowHistoryOwnerPredicate + `)`,
		`CREATE POLICY flow_history_owner ON ` + table + ` AS RESTRICTIVE FOR ALL TO PUBLIC USING (` + tenancy.FlowHistoryOwnerPredicate + `) WITH CHECK (true)`,
		`CREATE POLICY flow_history_owner ON ` + table + ` AS RESTRICTIVE FOR ALL TO PUBLIC USING (` + regrouped + `) WITH CHECK (` + regrouped + `)`,
	}
	for _, policy := range policies {
		if _, err := admin.Exec(ctx, plan[0]); err != nil {
			t.Fatal(err)
		}
		if policy != "" {
			if _, err := admin.Exec(ctx, policy); err != nil {
				t.Fatal(err)
			}
		}
		if err := tenancy.AssertFlowHistoryOwnerGuard(ctx, runtime, schema, "flow_conversation_messages"); err == nil {
			t.Fatal("startup posture accepted a missing/widened/permissive/role/command/check owner guard")
		}
		if policy == "" {
			var tenant string
			if err := admin.QueryRow(ctx, `SELECT tenant_id::text FROM `+table+` LIMIT 1`).Scan(&tenant); err != nil {
				t.Fatal(err)
			}
			err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), runtime, func(ctx context.Context, sc tenancy.Scope) error {
				return tenancy.AssertPostureTx(ctx, sc.Q)
			})
			if err == nil || !strings.Contains(err.Error(), "private history guard refused") {
				t.Fatal("complete startup path omitted the owner guard", err)
			}
		}
		for _, restore := range plan {
			if _, err := admin.Exec(ctx, restore); err != nil {
				t.Fatal(err)
			}
		}
		if err := tenancy.AssertFlowHistoryOwnerGuard(ctx, runtime, schema, "flow_conversation_messages"); err != nil {
			t.Fatal("exact restored owner guard remained unusable", err)
		}
	}
	for _, column := range []string{"tenant_id", "owner_id"} {
		quoted := pgx.Identifier{column}.Sanitize()
		if _, err := admin.Exec(ctx, `ALTER TABLE `+table+` ALTER COLUMN `+quoted+` DROP NOT NULL`); err != nil {
			t.Fatal(err)
		}
		if err := tenancy.AssertFlowHistoryOwnerGuard(ctx, runtime, schema, "flow_conversation_messages"); err == nil {
			t.Fatal("startup accepted nullable owner/tenant column")
		}
		if _, err := admin.Exec(ctx, `ALTER TABLE `+table+` ALTER COLUMN `+quoted+` SET NOT NULL`); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range []string{"probectl_provider", "PUBLIC"} {
		if _, err := admin.Exec(ctx, `GRANT SELECT ON `+table+` TO `+role); err != nil {
			t.Fatal(err)
		}
		if err := tenancy.AssertFlowHistoryOwnerGuard(ctx, runtime, schema, "flow_conversation_messages"); err == nil {
			t.Fatal("startup accepted a direct or inherited provider source grant")
		}
		if _, err := admin.Exec(ctx, `REVOKE SELECT ON `+table+` FROM `+role); err != nil {
			t.Fatal(err)
		}
	}
}
