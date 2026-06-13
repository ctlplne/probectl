// SPDX-License-Identifier: LicenseRef-probectl-TBD

package auth

import "testing"

// TestAuthorizeMatrix is the EXC-ORG-02 RBAC/ABAC depth matrix. It drives the
// single Authorize decision (tenant boundary FIRST, then RBAC, then ABAC) across
// the cases an F500 security reviewer checks: a permitted in-tenant action, the
// RBAC baseline (no permission = no access), ABAC overlays (step-up MFA, a
// contractor deny), CROSS-TENANT denial (a tenant-A principal can never act on a
// tenant-B resource even holding the permission), and LEAST-PRIVILEGE for a
// provider-operator-shaped principal (a provider role carries no tenant-data
// permissions, so it is denied tenant actions). A regression that lets any of the
// deny rows through reds the build.
func TestAuthorizeMatrix(t *testing.T) {
	const tenantA = "11111111-1111-1111-1111-111111111111"
	const tenantB = "22222222-2222-2222-2222-222222222222"

	// A normal tenant-A admin with MFA, holding incident + test write.
	adminA := &Principal{
		TenantID:    tenantA,
		UserID:      "u-admin",
		Permissions: map[string]bool{"incident.write": true, "test.write": true, "test.read": true},
		Attributes:  map[string]string{"role": "admin", "mfa": "true", "department": "netops"},
	}
	// A tenant-A contractor (no MFA) with test.write only.
	contractorA := &Principal{
		TenantID:    tenantA,
		UserID:      "u-contractor",
		Permissions: map[string]bool{"test.write": true},
		Attributes:  map[string]string{"role": "viewer", "mfa": "false", "department": "contractor"},
	}
	// A provider-operator-shaped principal: a SEPARATE privilege domain. Modeled
	// here with provider-plane permissions ONLY and no tenant-data permission —
	// it must never be authorized for a tenant action (least privilege; the
	// provider plane has NO implicit read of tenant telemetry, guardrail 1/7).
	providerOp := &Principal{
		TenantID:    tenantA, // even if it carries a tenant context
		UserID:      "op@msp.example",
		Permissions: map[string]bool{"provider.tenant.provision": true, "provider.metering.read": true},
		Attributes:  map[string]string{"role": "provider_operator", "mfa": "true"},
	}

	// Policy set: step-up MFA on incident.write; contractors denied test.write.
	policies := []Policy{
		pol("step-up", PolicyDeny, "incident.write", map[string]string{"mfa": "false"}, 5),
		pol("no-contractor-write", PolicyDeny, "test.write", map[string]string{"department": "contractor"}, 10),
	}

	resA := map[string]string{ResourceTenantKey: tenantA}
	resB := map[string]string{ResourceTenantKey: tenantB}

	cases := []struct {
		name       string
		p          *Principal
		permission string
		resource   map[string]string
		want       bool
		why        string
	}{
		{"admin in-tenant permitted", adminA, "test.write", resA, true, "RBAC granted, no deny, same tenant"},
		{"admin tenant-agnostic resource", adminA, "test.read", nil, true, "no resource tenant tag → no boundary check"},
		{"admin missing permission", adminA, "agent.write", resA, false, "RBAC baseline: permission not held"},
		{"admin mfa-satisfied incident.write", adminA, "incident.write", resA, true, "step-up satisfied (mfa=true)"},

		// ABAC overlays.
		{"contractor blocked by ABAC", contractorA, "test.write", resA, false, "ABAC deny overrides RBAC grant"},

		// Cross-tenant denial — the catastrophic failure (guardrail 1).
		{"admin denied cross-tenant resource", adminA, "test.write", resB, false, "tenant boundary fails closed BEFORE rbac"},
		{"admin denied cross-tenant even with mfa", adminA, "incident.write", resB, false, "tenant boundary is outermost"},

		// Least-privilege provider operator.
		{"provider op denied tenant action", providerOp, "test.write", resA, false, "no tenant-data permission held"},
		{"provider op denied incident.write", providerOp, "incident.write", resA, false, "least privilege: provider role ≠ tenant role"},
		{"provider op keeps its own perm", providerOp, "provider.tenant.provision", resA, true, "its own provider permission, in its tenant context"},

		// Nil principal is never authorized.
		{"nil principal", nil, "test.read", nil, false, "fail closed on no principal"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Authorize(tc.p, tc.permission, policies, tc.resource)
			if got != tc.want {
				t.Errorf("Authorize = %v, want %v (%s)", got, tc.want, tc.why)
			}
		})
	}
}

// TestAuthorizeTenantBoundaryIsOutermost proves the boundary is checked BEFORE
// RBAC: a principal holding the permission is still denied a cross-tenant
// resource, and the denial does not depend on any policy being present.
func TestAuthorizeTenantBoundaryIsOutermost(t *testing.T) {
	p := &Principal{
		TenantID:    "tenant-a",
		Permissions: map[string]bool{"test.read": true},
	}
	// Same tenant: permitted.
	if !Authorize(p, "test.read", nil, map[string]string{ResourceTenantKey: "tenant-a"}) {
		t.Fatal("same-tenant read with the permission must be permitted")
	}
	// Other tenant: denied even though RBAC would grant and no deny policy exists.
	if Authorize(p, "test.read", nil, map[string]string{ResourceTenantKey: "tenant-b"}) {
		t.Fatal("cross-tenant read must be denied at the boundary, before RBAC")
	}
	// An empty tenant tag is treated as tenant-agnostic (no boundary), so RBAC
	// alone decides — it must NOT be read as "matches everything and denies".
	if !Authorize(p, "test.read", nil, map[string]string{ResourceTenantKey: ""}) {
		t.Fatal("empty resource tenant tag must be tenant-agnostic (RBAC decides)")
	}
}
