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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestSiloDDLRunsAsTheMigrationLogin: a siloed tenant's schema is migration-
// class DDL. The serve login is least-privilege (TEN-01) and cannot create a
// schema, so the provisioner runs its DDL as the migration login when one is
// attached (PROBECTL_MIGRATE_DATABASE_URL) and, without it, refuses the
// provisioning with that instruction instead of a bare permission error.
func TestSiloDDLRunsAsTheMigrationLogin(t *testing.T) {
	ctx := context.Background()
	admin := itPool(t)
	defer admin.Close()

	run := time.Now().UnixNano()
	role := fmt.Sprintf("probectl_rt_silo_%d", run)
	const pw = "silo-ddl-pw"
	for _, stmt := range []string{
		`CREATE ROLE ` + role + ` LOGIN PASSWORD '` + pw + `' NOSUPERUSER NOBYPASSRLS`,
		`GRANT probectl_app TO ` + role,
		`GRANT probectl_provider TO ` + role + ` WITH INHERIT FALSE, SET TRUE`,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	u, err := url.Parse(testsupport.PostgresDSN())
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, pw)
	serve, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	tenantID := mkTenant(t, admin, fmt.Sprintf("silo-ddl-%d", run), "siloed", "")
	schema := SchemaName(tenantID)
	t.Cleanup(func() {
		serve.Close()
		_, _ = admin.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+quoteIdent(schema)+` CASCADE`)
		_, _ = admin.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})

	prov := NewProvisioner(serve, CHPlanes{}, nil, 7, nil)
	err = prov.Provision(ctx, tenantID, "", tenancy.IsolationSiloed)
	if err == nil || !strings.Contains(err.Error(), "PROBECTL_MIGRATE_DATABASE_URL") {
		t.Fatalf("siloed provisioning on the serve login alone = %v, want a refusal naming PROBECTL_MIGRATE_DATABASE_URL", err)
	}
	if schemaExists(t, admin, schema) {
		t.Fatal("the refused provisioning left a schema behind")
	}

	prov.WithDDLPool(admin)
	if err := prov.Provision(ctx, tenantID, "", tenancy.IsolationSiloed); err != nil {
		t.Fatalf("siloed provisioning with the migration login attached: %v", err)
	}
	if !schemaExists(t, admin, schema) {
		t.Fatalf("no schema %s after provisioning with the migration login", schema)
	}
	if err := prov.CatchUp(ctx, tenantID); err != nil {
		t.Fatalf("the catch-up a later boot runs: %v", err)
	}
}

func schemaExists(t *testing.T, pool *pgxpool.Pool, schema string) bool {
	t.Helper()
	var ok bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)`, schema).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}
