// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package rmm

import (
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	tenantAlpha  tenancy.ID = "00000000-0000-4000-8000-000000000001"
	tenantBeta   tenancy.ID = "00000000-0000-4000-8000-000000000002"
	contextAlpha            = "20000000-0000-4000-8000-000000000001"
	contextBeta             = "20000000-0000-4000-8000-000000000002"
)

func fixtureSite(tenant tenancy.ID, routingContext string, site Site) SiteMapping {
	return SiteMapping{Site: site, TenantID: tenant, ContextID: routingContext,
		EnrollURL: "https://control.example.invalid/", AgentGRPC: "control.example.invalid:9443"}
}

func fixtureSiteMappings(t *testing.T, routes ...SiteMapping) *SiteMappings {
	t.Helper()
	mappings, err := buildSiteMappings(routes)
	if err != nil {
		t.Fatal(err)
	}
	return mappings
}

func TestRMMSiteMappingsValidateDeploymentScope(t *testing.T) {
	ninja := Site{Vendor: NinjaOne, Account: "msp", ID: "42:7"}
	route := fixtureSite(tenantAlpha, contextAlpha, ninja)
	mappings := fixtureSiteMappings(t, route)
	ctx := tenancy.WithTenant(t.Context(), tenantAlpha)
	bound, err := mappings.Resolve(ctx, ninja)
	if err != nil || bound != route {
		t.Fatal("the tenant lookup did not return the exact deployment profile", err)
	}
	if _, err := mappings.Resolve(t.Context(), ninja); !errors.Is(err, tenancy.ErrNoTenant) {
		t.Fatalf("unscoped mapping lookup = %v", err)
	}
	for _, invalid := range []struct {
		name string
		edit func(*SiteMapping)
	}{
		{"noncanonical NinjaOne organization", func(p *SiteMapping) { p.ID = "042:7" }},
		{"out-of-range NinjaOne location", func(p *SiteMapping) { p.ID = "42:2147483648" }},
		{"off-route identifier", func(p *SiteMapping) { p.Vendor, p.ID = DattoRMM, ".." }},
		{"plaintext enrollment", func(p *SiteMapping) { p.EnrollURL = "http://control.example.invalid" }},
		{"user information", func(p *SiteMapping) { p.EnrollURL = "https://fixture-value@control.example.invalid" }},
		{"invalid gRPC port", func(p *SiteMapping) { p.AgentGRPC = "control.example.invalid:65536" }},
		{"invalid routing context", func(p *SiteMapping) { p.ContextID = "not-a-uuid" }},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			bad := route
			invalid.edit(&bad)
			if candidate, err := buildSiteMappings([]SiteMapping{bad}); err == nil || candidate != nil {
				t.Fatal("invalid site configuration was accepted")
			}
		})
	}
	if parsed, err := buildSiteMappings([]SiteMapping{route, fixtureSite(tenantBeta, contextBeta, ninja)}); err == nil || parsed != nil {
		t.Fatal("one RMM site was assigned twice")
	}
}
