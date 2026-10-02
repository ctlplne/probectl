// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// AUTHZ-02: a deprovisioned user (users.status <> 'active') must hold NO
// permissions even while their role bindings remain, so a re-login or a
// surviving token grants nothing. Reactivation restores access. Verified
// against real Postgres and the shipped migrations/queries.
func TestPermissionsForSubjectExcludesDisabledUser(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("authz02-%d", time.Now().UnixNano()), "authz02")
	if err != nil {
		t.Fatal(err)
	}

	var userID string
	count := func() int {
		t.Helper()
		var n int
		inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, sc tenancy.Scope) error {
			g, err := (Permissions{}).ForSubject(ctx, sc, "user", userID)
			if err != nil {
				return err
			}
			n = len(g)
			return nil
		})
		return n
	}
	setStatus := func(status string) {
		t.Helper()
		inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE users SET status = $1 WHERE id = $2::uuid`, status, userID)
			return err
		})
	}

	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if err := (Roles{}).EnsureSystemRoles(ctx, sc); err != nil {
			return err
		}
		u, err := (Users{}).Create(ctx, sc, "deprovisioned@authz02.test", "Dep User")
		if err != nil {
			return err
		}
		userID = u.ID
		admin, err := (Roles{}).GetBySlug(ctx, sc, "admin")
		if err != nil {
			return err
		}
		return (RoleBindings{}).Bind(ctx, sc, "user", u.ID, admin.ID)
	})

	if active := count(); active == 0 {
		t.Fatal("active admin user has no permissions (seed failed)")
	}
	setStatus("disabled")
	if got := count(); got != 0 {
		t.Fatalf("disabled user still holds %d permissions, want 0", got)
	}
	setStatus("active")
	if got := count(); got == 0 {
		t.Fatal("reactivated user still has no permissions")
	}
}
