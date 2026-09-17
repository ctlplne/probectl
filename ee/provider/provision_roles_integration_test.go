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
	var catalog int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM permissions`).Scan(&catalog); err != nil {
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
				if len(perms) != catalog {
					return fmt.Errorf("admin holds %d of %d catalog permissions", len(perms), catalog)
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
