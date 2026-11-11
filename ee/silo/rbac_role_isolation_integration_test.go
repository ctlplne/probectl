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

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestSiloRoleReferencesKeepTenantOnProvisionCatchupAndLegacyRefusal(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var tenants, roles, users [2]string
	for i := range tenants {
		tenant := mkTenant(t, pool, fmt.Sprintf("probectl-qa-beta-role-silo-%d-%d", i, time.Now().UnixNano()), "siloed", "")
		tenants[i] = tenant
		if err := provisioner.Provision(ctx, tenant, "", tenancy.IsolationSiloed); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := provisioner.Teardown(context.Background(), tenant, "", tenancy.IsolationSiloed); err != nil {
				t.Error(err)
			}
			if _, err := pool.Exec(context.Background(), `DELETE FROM public.tenants WHERE id=$1`, tenant); err != nil {
				t.Error(err)
			}
		})
		if err := roleReferenceSiloScope(ctx, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			role, err := (store.Roles{}).Create(ctx, sc, "finance", "Financial reader", "Own physical tenant")
			if err != nil {
				return err
			}
			roles[i] = role.ID
			if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, "flow.agreements.read"); err != nil {
				return err
			}
			user, err := (store.Users{}).Create(ctx, sc, "finance@local.test", "Financial reader")
			if err != nil {
				return err
			}
			users[i] = user.ID
			return (store.RoleBindings{}).Bind(ctx, sc, "user", user.ID, role.ID)
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertForeignRefused := func() {
		t.Helper()
		for i, tenant := range tenants {
			otherRole := roles[1-i]
			if err := roleReferenceSiloScope(ctx, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
				return (store.Roles{}).AddPermission(ctx, sc, otherRole, "flow.agreements.write")
			}); err == nil {
				t.Fatal("silo domain grant accepted a foreign parent role")
			}
			for _, child := range []string{"role_permissions", "role_bindings"} {
				err := roleReferenceSiloScope(ctx, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
					query := `INSERT INTO role_permissions(tenant_id,role_id,permission_key) VALUES($1,$2,'flow.agreements.write')`
					args := []any{tenant, otherRole}
					if child == "role_bindings" {
						query = `INSERT INTO role_bindings(tenant_id,role_id,subject_type,subject_id) VALUES($1,$2,'user',$3)`
						args = append(args, users[i])
					}
					_, err := sc.Q.Exec(ctx, query, args...)
					return err
				})
				var rejected *pgconn.PgError
				if !errors.As(err, &rejected) || rejected.Code != "23503" || rejected.ConstraintName != child+"_tenant_role_fk" {
					t.Fatal("actual physical silo admitted a foreign role reference", child, err)
				}
			}
			if err := roleReferenceSiloScope(ctx, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
				grants, err := (store.Roles{}).Permissions(ctx, sc, roles[i])
				if err != nil || len(grants) != 1 || grants[0] != "flow.agreements.read" {
					return fmt.Errorf("silo sibling or owner grants changed: %v %w", grants, err)
				}
				effective, err := (store.Permissions{}).ForSubject(ctx, sc, "user", users[i])
				if err != nil || len(effective) != 1 || effective[0].Permission != "flow.agreements.read" {
					return fmt.Errorf("silo effective permissions crossed parent ownership: %v %w", effective, err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	assertForeignRefused()
	// Restore the precise pre-fix condition only in this owned test silo:
	// LIKE omitted FKs, allowing a child tenant to name a foreign parent.
	first := quoteIdent(SchemaName(tenants[0]))
	for _, child := range []string{"role_permissions", "role_bindings"} {
		if _, err := pool.Exec(ctx, "ALTER TABLE "+first+"."+quoteIdent(child)+" DROP CONSTRAINT "+quoteIdent(child+"_tenant_role_fk")); err != nil {
			t.Fatal(err)
		}
	}
	if err := roleReferenceSiloScope(ctx, pool, tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO role_permissions(tenant_id,role_id,permission_key) VALUES($1,$2,'flow.agreements.write')`, tenants[0], roles[1]); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO role_bindings(tenant_id,role_id,subject_type,subject_id) VALUES($1,$2,'user',$3)`, tenants[0], roles[1], users[0])
		return err
	}); err != nil {
		t.Fatal("controlled legacy silo did not reproduce its missing parent-tenant constraint", err)
	}
	if err := roleReferenceSiloScope(ctx, pool, tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		grants, err := (store.Permissions{}).ForSubject(ctx, sc, "user", users[0])
		if err != nil || len(grants) != 1 || grants[0].Permission != "flow.agreements.read" {
			return fmt.Errorf("legacy foreign-parent pair granted a permission before validation: %v %w", grants, err)
		}
		foreign, err := (store.Roles{}).Permissions(ctx, sc, roles[1])
		if err != nil || len(foreign) != 0 {
			return fmt.Errorf("legacy foreign role exposed grant keys: %v %w", foreign, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := provisioner.CatchUpSchema(ctx, tenants[0]); err == nil {
		t.Fatal("catch-up silently accepted a historical inconsistent role reference")
	}
	var remaining, bindings int
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM "+first+`.role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='flow.agreements.write'),(SELECT count(*) FROM `+first+`.role_bindings WHERE tenant_id=$1 AND role_id=$2)`, tenants[0], roles[1]).Scan(&remaining, &bindings); err != nil || remaining != 1 || bindings != 1 {
		t.Fatal("validation failure discarded or reassigned a historical fixture", remaining, bindings, err)
	}
	// Remove only the intentionally planted test row, then prove repair is
	// idempotent and the same raw operation is refused after catch-up.
	for _, child := range []string{"role_bindings", "role_permissions"} {
		if _, err := pool.Exec(ctx, "DELETE FROM "+first+"."+quoteIdent(child)+` WHERE tenant_id=$1 AND role_id=$2`, tenants[0], roles[1]); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := provisioner.CatchUpSchema(ctx, tenants[0]); err != nil {
			t.Fatal(err)
		}
	}
	assertForeignRefused()
	sql, err := migrations.FS.ReadFile("0193_rbac_role_tenant_references.sql")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatal("repeat role ownership migration failed", err)
		}
	}
	assertForeignRefused()
	t.Log("real-integration: actual Postgres, shipped physical silo provision/catch-up, application-role RLS, foreign-parent refusal, legacy validation without automatic deletion and repeat migration; served user authorization is separate")
}

func roleReferenceSiloScope(ctx context.Context, pool *pgxpool.Pool, tenant string, fn func(context.Context, tenancy.Scope) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE probectl_app"); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('probectl.tenant_id',$1,true)", tenant); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "SET LOCAL search_path TO "+quoteIdent(SchemaName(tenant))+",public"); err != nil {
		return err
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	if err := fn(ctx, tenancy.Scope{Tenant: tenancy.ID(tenant), Q: tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
