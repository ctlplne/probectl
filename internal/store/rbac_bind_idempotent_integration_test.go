// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// DPR-015: binding the same subject to the same role at tenant scope twice
// (a SCIM group re-add, a bootstrap-admin re-run) must leave exactly one row,
// and Unbind must remove it.
func TestRoleBindingsBindIsIdempotentAtTenantScope(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	suffix := time.Now().UnixNano()
	tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("bind-%d", suffix), "Bind")
	if err != nil {
		t.Fatal(err)
	}
	inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, scope tenancy.Scope) error {
		user, err := (Users{}).Create(ctx, scope, fmt.Sprintf("bind-%d@example.test", suffix), "Bind User")
		if err != nil {
			return err
		}
		role, err := (Roles{}).Create(ctx, scope, "bind-admin", "Bind admin", "")
		if err != nil {
			return err
		}
		for i := 0; i < 3; i++ {
			if err := (RoleBindings{}).Bind(ctx, scope, "user", user.ID, role.ID); err != nil {
				return fmt.Errorf("bind #%d: %w", i+1, err)
			}
		}
		var n int
		if err := scope.Q.QueryRow(ctx,
			`SELECT count(*) FROM role_bindings WHERE subject_type = 'user' AND subject_id = $1 AND role_id = $2`,
			user.ID, role.ID).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Fatalf("three binds must leave one row, got %d", n)
		}
		if err := (RoleBindings{}).Unbind(ctx, scope, "user", user.ID, role.ID); err != nil {
			return err
		}
		if err := scope.Q.QueryRow(ctx,
			`SELECT count(*) FROM role_bindings WHERE subject_type = 'user' AND subject_id = $1 AND role_id = $2`,
			user.ID, role.ID).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("unbind must remove the binding, got %d", n)
		}
		return nil
	})
}
