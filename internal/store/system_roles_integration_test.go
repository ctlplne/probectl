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
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// DPR-035: a fresh tenant gets the three system roles with the same
// permission rules migration 0013 gave the default tenant, idempotently, and
// the seed never leaks into another tenant.
func TestEnsureSystemRolesSeedsAFreshTenantIdempotently(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("roles-%d", time.Now().UnixNano()), "Roles Tenant")
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewTenants(pool).Create(ctx, fmt.Sprintf("roles-other-%d", time.Now().UnixNano()), "Other")
	if err != nil {
		t.Fatal(err)
	}
	var catalog int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM permissions`).Scan(&catalog); err != nil {
		t.Fatal(err)
	}
	for range 2 { // second run must be a no-op
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			return (Roles{}).EnsureSystemRoles(ctx, sc)
		}); err != nil {
			t.Fatalf("ensure: %v", err)
		}
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		roles, total, err := (Roles{}).ListPage(ctx, sc, 1, 50)
		if err != nil {
			return err
		}
		if total != 3 {
			return fmt.Errorf("roles = %d, want exactly admin/editor/viewer", total)
		}
		for _, r := range roles {
			perms, err := (Roles{}).Permissions(ctx, sc, r.ID)
			if err != nil {
				return err
			}
			switch r.Slug {
			case "admin":
				if len(perms) != catalog {
					return fmt.Errorf("admin holds %d of %d catalog permissions", len(perms), catalog)
				}
			case "viewer":
				for _, p := range perms {
					if len(p) < 5 || p[len(p)-5:] != ".read" {
						return fmt.Errorf("viewer holds a non-read permission %q", p)
					}
				}
			case "editor":
				want := map[string]bool{"test.write": true, "alert.write": true, "incident.write": true}
				for _, p := range perms {
					if p[len(p)-5:] != ".read" && !want[p] {
						return fmt.Errorf("editor holds an unexpected write %q", p)
					}
				}
			}
			if !r.IsSystem {
				return fmt.Errorf("%s must be a system role", r.Slug)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(other.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := (Roles{}).GetBySlug(ctx, sc, "admin"); err == nil {
			return fmt.Errorf("seeding tenant A must not create roles in tenant B")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
