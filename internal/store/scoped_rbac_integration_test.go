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

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func TestScopedRBACTenantIsolationPreservesBindingScope(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	suffix := time.Now().UnixNano()
	tenantA, err := NewTenants(pool).Create(ctx, fmt.Sprintf("scope-a-%d", suffix), "Scope A")
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := NewTenants(pool).Create(ctx, fmt.Sprintf("scope-b-%d", suffix), "Scope B")
	if err != nil {
		t.Fatal(err)
	}

	var userID, orgAID string
	inTenant(ctx, t, pool, tenantA.ID, func(ctx context.Context, scope tenancy.Scope) error {
		user, err := (Users{}).Create(ctx, scope, fmt.Sprintf("scope-%d@example.test", suffix), "Scoped User")
		if err != nil {
			return err
		}
		userID = user.ID
		org, err := (Organizations{}).Create(ctx, scope, "alpha", "Alpha")
		if err != nil {
			return err
		}
		orgAID = org.ID
		role, err := (Roles{}).Create(ctx, scope, "org-editor", "Org editor", "")
		if err != nil {
			return err
		}
		if err := (Roles{}).AddPermission(ctx, scope, role.ID, "org.write"); err != nil {
			return err
		}
		_, err = (RoleBindings{}).Create(ctx, scope, "user", user.ID, role.ID, "org", &org.ID)
		return err
	})

	inTenant(ctx, t, pool, tenantA.ID, func(ctx context.Context, scope tenancy.Scope) error {
		grants, err := (Permissions{}).ForSubject(ctx, scope, "user", userID)
		if err != nil {
			return err
		}
		want := auth.PermissionGrant{Permission: "org.write", ScopeType: auth.ScopeOrganization, ScopeID: orgAID}
		if len(grants) != 1 || grants[0] != want {
			t.Fatalf("tenant A grants = %#v, want %#v", grants, want)
		}
		return nil
	})

	// The same subject UUID queried under tenant B is empty because role
	// bindings and role permissions are FORCE-RLS confined before RBAC.
	inTenant(ctx, t, pool, tenantB.ID, func(ctx context.Context, scope tenancy.Scope) error {
		grants, err := (Permissions{}).ForSubject(ctx, scope, "user", userID)
		if err != nil {
			return err
		}
		if len(grants) != 0 {
			t.Fatalf("tenant B loaded tenant A grants: %#v", grants)
		}
		return nil
	})
}
