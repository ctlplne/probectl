// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Commercial code; see ee/LICENSE.

//go:build integration

package provider

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// DPR-035: a tenant provisioned through the provider plane is born with its
// system roles, so the first administrator can be granted at once.
func TestProvisionSeedsSystemRolesInTheNewTenant(t *testing.T) {
	ctx := context.Background()
	pool := pgPool(t)
	st := NewPGStore(pool)
	svc, err := NewService(st, newIntegrationProviderAudit(t, pool),
		licenseManager(t, license.TierMSP, 0, 90*24*time.Hour), fakeTelemetry{}, testEnvelope(t), 4*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	svc.WithRoleSeeder(func(ctx context.Context, tenantID string) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).EnsureSystemRoles(ctx, sc)
		})
	})
	slug := fmt.Sprintf("seeded-%d", time.Now().UnixNano())
	tenant, err := svc.Provision(ctx, "ops@example.com", slug, "Seeded Tenant", "pooled", "")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	// AUTHZ-09: admin holds every catalog permission EXCEPT the
	// separation-of-duty keys (ir.investigate), which belong only to a dedicated
	// ir-investigator role. So admin must hold the whole catalog minus the SoD
	// key(s), and must NOT hold ir.investigate.
	var catalogKeys []string
	rows, err := pool.Query(ctx, `SELECT key FROM permissions ORDER BY key`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		catalogKeys = append(catalogKeys, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		for _, slug := range []string{"admin", "editor", "viewer"} {
			r, err := (store.Roles{}).GetBySlug(ctx, sc, slug)
			if err != nil {
				return fmt.Errorf("role %s missing in the new tenant: %w", slug, err)
			}
			if slug == "admin" {
				perms, err := (store.Roles{}).Permissions(ctx, sc, r.ID)
				if err != nil {
					return err
				}
				have := make(map[string]bool, len(perms))
				for _, k := range perms {
					have[k] = true
				}
				if have["ir.investigate"] {
					return fmt.Errorf("admin must NOT hold the separation-of-duty key ir.investigate (AUTHZ-09)")
				}
				var missing []string
				for _, k := range catalogKeys {
					if k == "ir.investigate" {
						continue // the one SoD key admin is expected to lack
					}
					if !have[k] {
						missing = append(missing, k)
					}
				}
				if len(missing) != 0 {
					return fmt.Errorf("admin missing non-SoD catalog permissions: %v", missing)
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
