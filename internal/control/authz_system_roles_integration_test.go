// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"net/http"
	"testing"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestSystemRolesExcludeOperatorAndSoDKeys is the AUTHZ-07 / AUTHZ-09 regression:
// a newly provisioned tenant's system roles must NOT grant the operator/provider-
// infrastructure reads (diagnostics.read, fairness.read) to viewer/editor, nor
// the separation-of-duty key ir.investigate to admin. It also asserts the
// directory API refuses to bind the ir-investigator role.
func TestSystemRolesExcludeOperatorAndSoDKeys(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	h := srv.Handler()
	ctx := context.Background()

	tenantID := freshTenant(t, db, "authz79")

	perms := map[string][]string{}
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		if e := (store.Roles{}).EnsureSystemRoles(ctx, sc); e != nil {
			return e
		}
		rows, e := sc.Q.Query(ctx, `SELECT r.slug, rp.permission_key
			FROM role_permissions rp JOIN roles r ON r.id = rp.role_id
			WHERE r.is_system`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var slug, key string
			if e := rows.Scan(&slug, &key); e != nil {
				return e
			}
			perms[slug] = append(perms[slug], key)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("seed/query system roles: %v", err)
	}

	has := func(slug, key string) bool {
		for _, k := range perms[slug] {
			if k == key {
				return true
			}
		}
		return false
	}

	// AUTHZ-07: viewer and editor must not hold the operator/provider-infra reads.
	for _, slug := range []string{"viewer", "editor"} {
		for _, key := range []string{"diagnostics.read", "fairness.read"} {
			if has(slug, key) {
				t.Errorf("%s role holds operator-only %q (AUTHZ-07: deployment-global/provider data leaks to read-only tenant users)", slug, key)
			}
		}
		// Sanity: the role is still seeded with ordinary reads.
		if !has(slug, "test.read") {
			t.Errorf("%s role lost test.read; seeding is broken", slug)
		}
	}
	// AUTHZ-09: admin must not hold the SoD key (held only by ir-investigator).
	if has("admin", "ir.investigate") {
		t.Errorf("admin role holds ir.investigate (AUTHZ-09: IR-attribution separation of duty broken)")
	}
	// Sanity: admin is still broadly privileged.
	if !has("admin", "test.write") {
		t.Error("admin role lost test.write; seeding is broken")
	}

	// AUTHZ-09: EVERY directory bind path must refuse the ir-investigator role —
	// the role-bind endpoint AND the user-create endpoint (which binds a role by
	// slug in the same step).
	uid := createUserWithPerm(t, db, tenantID, "authz79@x.com", nil, "test.read")
	if rec := apiReq(t, h, http.MethodPost, "/v1/directory/users/"+uid+"/roles", tenantID, map[string]any{"role": "ir-investigator"}); rec.Code != http.StatusForbidden {
		t.Fatalf("directory role-bind of ir-investigator = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if rec := apiReq(t, h, http.MethodPost, "/v1/directory/users", tenantID, map[string]any{"email": "ir-sneak@x.com", "role": "ir-investigator"}); rec.Code != http.StatusForbidden {
		t.Fatalf("directory user-create with ir-investigator = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}
