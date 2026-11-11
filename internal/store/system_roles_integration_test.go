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
	var delegatedID string
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
			hasPermission := func(key string) bool {
				for _, permission := range perms {
					if permission == key {
						return true
					}
				}
				return false
			}
			if !hasPermission("nms.import.read") {
				return fmt.Errorf("%s must be able to read redacted import plans", r.Slug)
			}
			if hasPermission("nms.import.write") != (r.Slug == "admin") {
				return fmt.Errorf("%s has unexpected NMS import write grant", r.Slug)
			}
			if !hasPermission("tags.read") {
				return fmt.Errorf("%s must be able to read tenant tags", r.Slug)
			}
			if hasPermission("tags.write") != (r.Slug == "admin") {
				return fmt.Errorf("%s has unexpected tag write grant", r.Slug)
			}
			for _, permission := range []string{"flow.agreements.read", "flow.agreements.write"} {
				if hasPermission(permission) != (r.Slug == "admin") {
					return fmt.Errorf("%s has unexpected financial agreement grant %q", r.Slug, permission)
				}
			}
			if !hasPermission("flow.read") {
				return fmt.Errorf("%s lost ordinary telemetry read access", r.Slug)
			}
			switch r.Slug {
			case "admin":
				// AUTHZ-09 (migrations 0081/0103, rbac.go): the tenant admin holds
				// every catalog permission EXCEPT the separation-of-duty keys, which
				// live only on their dedicated role (ir.investigate → ir-investigator).
				// So the expected count is the catalog minus those SoD keys, and admin
				// must hold NONE of them.
				if len(perms) != catalog-len(sodPermissionKeys) {
					return fmt.Errorf(
						"admin holds %d of %d catalog permissions, want all except the %d separation-of-duty key(s) %v",
						len(perms), catalog, len(sodPermissionKeys), sodPermissionKeys,
					)
				}
				for _, p := range perms {
					for _, sod := range sodPermissionKeys {
						if p == sod {
							return fmt.Errorf("admin must not hold separation-of-duty key %q (AUTHZ-09)", sod)
						}
					}
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
		delegated, err := (Roles{}).Create(ctx, sc, "finance-reader", "Financial reader", "Explicit recorded-term delegation")
		if err != nil {
			return err
		}
		delegatedID = delegated.ID
		if err := (Roles{}).AddPermission(ctx, sc, delegated.ID, "flow.agreements.read"); err != nil {
			return err
		}
		grants, err := (Roles{}).Permissions(ctx, sc, delegated.ID)
		if err != nil || len(grants) != 1 || grants[0] != "flow.agreements.read" {
			return fmt.Errorf("explicit financial read delegation changed its exact scope: %v %w", grants, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(other.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := (Roles{}).GetBySlug(ctx, sc, "admin"); err == nil {
			return fmt.Errorf("seeding tenant A must not create roles in tenant B")
		}
		grants, err := (Roles{}).Permissions(ctx, sc, delegatedID)
		if err != nil || len(grants) != 0 {
			return fmt.Errorf("foreign financial role grants crossed storage isolation: %v %w", grants, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(other.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		return (Roles{}).AddPermission(ctx, sc, delegatedID, "flow.agreements.write")
	}); err == nil {
		t.Fatal("storage admitted a foreign financial role reference")
	}
}
