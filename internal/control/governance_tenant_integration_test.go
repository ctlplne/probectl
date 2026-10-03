// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"net/http"
	"testing"

	"github.com/ctlplne/probectl/internal/govern"
)

// The real-stack receipt for AUD-12: a tenant admin reads and updates its OWN
// governance policy (incl ai_remote_egress) through /v1, the change persists and
// is isolated to that tenant at the storage layer (RLS), and the change lands in
// that tenant's tamper-evident audit chain — while the write itself runs through
// the provider role under a bound tenant GUC (the tenant app role stays
// write-fenced off tenant_governance, migration 0111). The handler-level
// contract (hidden-unlicensed 404, RBAC gating, tenant-from-context, audit
// wiring) is proved in governanceapi_test.go without a database; this proves the
// properties that only a real Postgres with roles + RLS + the audit chain can.
func TestGovernancePolicyTenantManagementRealStack(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	srv.WithGovernance(govern.NewPolicyStore(db.Pool()))
	h := srv.Handler()

	tenantA := freshTenant(t, db, "gov-a")
	tenantB := freshTenant(t, db, "gov-b")

	// Both tenants start at the default (no row): consent is false.
	if egress := getPolicyEgress(t, h, tenantA); egress {
		t.Fatalf("tenant A default ai_remote_egress = true, want false")
	}
	if egress := getPolicyEgress(t, h, tenantB); egress {
		t.Fatalf("tenant B default ai_remote_egress = true, want false")
	}

	// Tenant A's admin grants the remote-AI egress consent through the API.
	if rec := apiReq(t, h, http.MethodPut, "/v1/governance/policy", tenantA,
		map[string]any{"ai_remote_egress": true, "redact_export": true}); rec.Code != http.StatusOK {
		t.Fatalf("PUT governance policy as A: %d %s", rec.Code, rec.Body)
	}

	// It persisted for A, read back through the tenant RLS read path...
	if egress := getPolicyEgress(t, h, tenantA); !egress {
		t.Fatalf("after PUT, tenant A ai_remote_egress = false, want true")
	}
	// ...and did NOT leak into B (storage-layer isolation, G7-1).
	if egress := getPolicyEgress(t, h, tenantB); egress {
		t.Fatalf("tenant B ai_remote_egress = true after only A was changed — isolation breach")
	}

	// The change is in A's tamper-evident audit chain, and A's chain verifies.
	if !hasGovernanceAudit(t, h, tenantA) {
		t.Fatalf("tenant A audit chain missing %q after the policy change (G7-7)", governancePolicyAuditAction)
	}
	if ok, detail := verifyAudit(t, h, tenantA); !ok {
		t.Fatalf("tenant A audit chain should verify clean after the governance append: %s", detail)
	}
	// B's chain never received A's receipt (audit isolation).
	if hasGovernanceAudit(t, h, tenantB) {
		t.Fatalf("tenant B audit chain contains A's governance change — audit isolation breach")
	}

	// Cross-tenant write isolation the other way: B sets its own consent; A's
	// value is unchanged and both tenants hold independent policies.
	if rec := apiReq(t, h, http.MethodPut, "/v1/governance/policy", tenantB,
		map[string]any{"ai_remote_egress": true}); rec.Code != http.StatusOK {
		t.Fatalf("PUT governance policy as B: %d %s", rec.Code, rec.Body)
	}
	if egress := getPolicyEgress(t, h, tenantA); !egress {
		t.Fatalf("tenant A ai_remote_egress flipped under a tenant B write — isolation breach")
	}
	if egress := getPolicyEgress(t, h, tenantB); !egress {
		t.Fatalf("after PUT, tenant B ai_remote_egress = false, want true")
	}
}

func getPolicyEgress(t *testing.T, h http.Handler, tenant string) bool {
	t.Helper()
	rec := apiReq(t, h, http.MethodGet, "/v1/governance/policy", tenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET governance policy as %s: %d %s", tenant, rec.Code, rec.Body)
	}
	var body struct {
		AIRemoteEgress bool `json:"ai_remote_egress"`
	}
	mustJSON(t, rec, &body)
	return body.AIRemoteEgress
}

func hasGovernanceAudit(t *testing.T, h http.Handler, tenant string) bool {
	t.Helper()
	for _, ev := range listAudit(t, h, tenant) {
		if ev.Action == governancePolicyAuditAction {
			return true
		}
	}
	return false
}
