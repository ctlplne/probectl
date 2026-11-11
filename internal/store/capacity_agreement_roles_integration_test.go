// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/migrations"
)

func TestCapacityAgreementRoleMigrationKeepsPrivateSchemasAndExplicitDelegation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	var tenants, schemas [2]string
	for i := range tenants {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("probectl-qa-beta-finance-grants-%d-%d", i, time.Now().UnixNano()), "Own financial grant fixture")
		if err != nil {
			t.Fatal(err)
		}
		tenants[i] = tenant.ID
		t.Cleanup(func() {
			if _, err := pool.Exec(context.Background(), `DELETE FROM public.tenants WHERE id=$1`, tenant.ID); err != nil {
				t.Error(err)
			}
		})
		inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
			if err := (Roles{}).EnsureSystemRoles(ctx, sc); err != nil {
				return err
			}
			role, err := (Roles{}).Create(ctx, sc, "finance-reader", "Financial reader", "Explicit delegation")
			if err != nil {
				return err
			}
			return (Roles{}).AddPermission(ctx, sc, role.ID, "flow.agreements.read")
		})
		schema := "t_" + strings.ReplaceAll(tenant.ID, "-", "")
		schemas[i] = pgx.Identifier{schema}.Sanitize()
		if _, err := pool.Exec(ctx, "CREATE SCHEMA "+schemas[i]); err != nil {
			t.Fatal(err)
		}
		qualified := schemas[i]
		t.Cleanup(func() {
			if _, err := pool.Exec(context.Background(), "DROP SCHEMA "+qualified+" CASCADE"); err != nil {
				t.Error(err)
			}
		})
		for _, table := range []string{"roles", "role_permissions"} {
			name := pgx.Identifier{table}.Sanitize()
			if _, err := pool.Exec(ctx, "CREATE TABLE "+qualified+"."+name+" (LIKE public."+name+" INCLUDING ALL)"); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, "INSERT INTO "+qualified+"."+name+" SELECT * FROM public."+name+" WHERE tenant_id=$1", tenant.ID); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := pool.Exec(ctx, "DELETE FROM "+qualified+".role_permissions rp USING "+qualified+".roles r WHERE rp.tenant_id=$1 AND r.tenant_id=$1 AND rp.role_id=r.id AND r.slug='admin' AND rp.permission_key IN ('flow.agreements.read','flow.agreements.write')", tenant.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, "INSERT INTO "+qualified+".role_permissions(tenant_id,role_id,permission_key) SELECT r.tenant_id,r.id,p.key FROM "+qualified+".roles r CROSS JOIN public.permissions p WHERE r.tenant_id=$1 AND r.slug='viewer' AND p.key IN ('flow.agreements.read','flow.agreements.write')", tenant.ID); err != nil {
			t.Fatal(err)
		}
	}
	// A misplaced foreign fixture row must not be selected merely because
	// the migration is walking this physical schema as its owner.
	if _, err := pool.Exec(ctx, "INSERT INTO "+schemas[0]+".roles SELECT * FROM public.roles WHERE tenant_id=$1 AND slug='admin'", tenants[1]); err != nil {
		t.Fatal(err)
	}
	sql, err := migrations.FS.ReadFile("0192_capacity_agreement_permissions.sql")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatal("repeat permission expansion failed", err)
		}
	}
	for i, schema := range schemas {
		for _, expected := range []struct {
			slug  string
			count int
		}{{"admin", 2}, {"viewer", 0}, {"editor", 0}, {"finance-reader", 1}} {
			var count int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+schema+".role_permissions rp JOIN "+schema+".roles r ON r.tenant_id=rp.tenant_id AND r.id=rp.role_id WHERE rp.tenant_id=$1 AND r.slug=$2 AND rp.permission_key IN ('flow.agreements.read','flow.agreements.write')", tenants[i], expected.slug).Scan(&count); err != nil || count != expected.count {
				t.Fatal("private-schema financial defaults or explicit delegation changed", i, expected, count, err)
			}
		}
	}
	var foreign int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+schemas[0]+".role_permissions WHERE tenant_id=$1", tenants[1]).Scan(&foreign); err != nil || foreign != 0 {
		t.Fatal("migration granted a misplaced foreign role inside the other schema", foreign, err)
	}
	t.Log("real-integration: actual TLS PostgreSQL permission migration against modeled private RBAC schemas; complete silo provisioning/RLS proof remains separate")
}
