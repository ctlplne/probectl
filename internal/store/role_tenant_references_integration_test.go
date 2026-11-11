// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRoleGrantsBindParentTenantBeforeInsertUpdateAndPermissionRead(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	type subject struct{ tenant, role, user string }
	var subjects [2]subject
	for i := range subjects {
		f := &subjects[i]
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("probectl-qa-beta-role-parent-%d-%d", i, time.Now().UnixNano()), "Role reference boundary")
		if err != nil {
			t.Fatal(err)
		}
		f.tenant = tenant.ID
		t.Cleanup(func() {
			if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
				t.Error(err)
			}
		})
		inTenant(ctx, t, pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			role, err := (Roles{}).Create(ctx, sc, "financial-reader", "Financial reader", "Own tenant")
			if err != nil {
				return err
			}
			f.role = role.ID
			user, err := (Users{}).Create(ctx, sc, "reader@local.test", "Own reader")
			if err != nil {
				return err
			}
			f.user = user.ID
			for range 2 {
				if err := (Roles{}).AddPermission(ctx, sc, role.ID, "flow.agreements.read"); err != nil {
					return err
				}
			}
			return (RoleBindings{}).Bind(ctx, sc, "user", user.ID, role.ID)
		})
	}
	for i, own := range subjects {
		foreign := subjects[1-i]
		bound := tenancy.WithTenant(ctx, tenancy.ID(own.tenant))
		if err := tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
			return (Roles{}).AddPermission(ctx, sc, foreign.role, "flow.agreements.write")
		}); err == nil {
			t.Fatal("foreign role admitted a domain grant")
		}
		for _, attempt := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO role_permissions(tenant_id,role_id,permission_key) VALUES($1,$2,'flow.agreements.write')`, []any{own.tenant, foreign.role}},
			{`UPDATE role_permissions SET role_id=$2,permission_key='flow.agreements.write' WHERE tenant_id=$1 AND role_id=$3`, []any{own.tenant, foreign.role, own.role}},
			{`INSERT INTO role_bindings(tenant_id,role_id,subject_type,subject_id) VALUES($1,$2,'user',$3)`, []any{own.tenant, foreign.role, own.user}},
			{`UPDATE role_bindings SET role_id=$2 WHERE tenant_id=$1 AND role_id=$3`, []any{own.tenant, foreign.role, own.role}},
		} {
			err := tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, attempt.sql, attempt.args...)
				return err
			})
			var rejected *pgconn.PgError
			if !errors.As(err, &rejected) || rejected.Code != "23503" {
				t.Fatal("raw role reference bypassed the storage tenant foreign key", attempt.sql, err)
			}
		}
		inTenant(ctx, t, pool, own.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			grants, err := (Permissions{}).ForSubject(ctx, sc, "user", own.user)
			if err != nil || len(grants) != 1 || grants[0].Permission != "flow.agreements.read" {
				return fmt.Errorf("refused foreign writes changed own effective financial permission: %v %w", grants, err)
			}
			foreignGrants, err := (Roles{}).Permissions(ctx, sc, foreign.role)
			if err != nil || len(foreignGrants) != 0 {
				return fmt.Errorf("foreign role read escaped parent tenant: %v %w", foreignGrants, err)
			}
			return nil
		})
	}
	for _, own := range subjects {
		inTenant(ctx, t, pool, own.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			// A rejected foreign write must not reserve the owner's grant key.
			return (Roles{}).AddPermission(ctx, sc, own.role, "flow.agreements.write")
		})
	}
}
