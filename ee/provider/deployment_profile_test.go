// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/license"
)

// newProfileService builds a provider Service over the in-memory fakes with a
// given deployment profile/scoping posture and an UNLIMITED license band (band
// 0), so the ONLY creation ceiling under test is the deployment-profile guard,
// never the licensed tenant band.
func newProfileService(t *testing.T, profile string, chTenantScoped bool) *Service {
	t.Helper()
	svc, err := NewService(
		NewMemStore(),
		&memAudit{},
		licenseManager(t, license.TierMSP, 0, 90*24*time.Hour),
		fakeTelemetry{byTenant: map[string][]string{}},
		testEnvelope(t),
		4*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	return svc.WithDeploymentProfile(profile, chTenantScoped)
}

// TestProvisionRefusesSecondTenantUnderSingleProfile is the TEN-04 / VER-02
// regression: through the REAL Provision entry point, the degraded single-tenant
// profile admits exactly one tenant and refuses the second at CREATION time
// (previously only the boot-time AssertDeploymentProfilePosture caught it, so a
// tenant provisioned at runtime slipped past and crash-looped the next restart).
// The refusal is the typed ErrSingleProfileTenantCap and its message names the
// profile and the scoping flags an operator can set to proceed.
func TestProvisionRefusesSecondTenantUnderSingleProfile(t *testing.T) {
	ctx := context.Background()
	svc := newProfileService(t, "single", false)

	// The first tenant is fine — a single-tenant deployment is meant to have one.
	if _, err := svc.Provision(ctx, "ops@msp.example", "acme", "Acme", "pooled", ""); err != nil {
		t.Fatalf("first tenant under single profile: unexpected error %v", err)
	}

	// The second would push the deployment past its one-tenant ceiling: refused.
	_, err := svc.Provision(ctx, "ops@msp.example", "globex", "Globex", "pooled", "")
	if !errors.Is(err, ErrSingleProfileTenantCap) {
		t.Fatalf("second tenant under single profile: error = %v, want ErrSingleProfileTenantCap", err)
	}
	// The message must be actionable: name the profile knob AND the scoping flags.
	for _, want := range []string{
		"PROBECTL_DEPLOYMENT_PROFILE",
		"PROBECTL_INGEST_STRICT_TENANT_LANES",
		"TENANT_SCOPING",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal message %q does not name %q", err.Error(), want)
		}
	}

	// The refusal is at creation: the second tenant must not have landed.
	tenants, err := svc.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tenants) != 1 {
		t.Fatalf("active tenants after refused provision = %d, want 1", len(tenants))
	}
}

// TestProvisionAllowsMultipleTenantsOffSingleProfile proves the guard is scoped
// to the degraded single profile only: a multi-tenant deployment, and a single
// profile that has explicitly completed ClickHouse/bus tenant scoping (not
// degraded, exactly as AssertDeploymentProfilePosture treats it), both admit a
// second tenant. This is the no-over-refusal half of TEN-04 / VER-02.
func TestProvisionAllowsMultipleTenantsOffSingleProfile(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name           string
		profile        string
		chTenantScoped bool
	}{
		{"multi-tenant profile", "multi-tenant", false},
		{"regulated profile", "regulated", false},
		{"single profile with scoping complete", "single", true},
		{"profile unset (unit default, gate inert)", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newProfileService(t, tc.profile, tc.chTenantScoped)
			if _, err := svc.Provision(ctx, "ops@msp.example", "acme", "Acme", "pooled", ""); err != nil {
				t.Fatalf("first tenant: unexpected error %v", err)
			}
			if _, err := svc.Provision(ctx, "ops@msp.example", "globex", "Globex", "pooled", ""); err != nil {
				t.Fatalf("second tenant: unexpected error %v", err)
			}
		})
	}
}
