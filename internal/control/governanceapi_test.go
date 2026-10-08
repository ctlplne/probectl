// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// fakeGovStore is an in-test governancePolicyStore. The control plane holds the
// store behind an interface so the handler suite can drive the tenant-scoping
// and audit-wiring contract without a database; the real-stack isolation and
// tenant-audit-chain assertions live in the //go:build integration receipt.
type fakeGovStore struct {
	policies      map[string]govern.Policy // GET result, keyed by tenant
	lastSetTenant string
	lastSetPol    govern.Policy
	setN          int
	auditProvided bool
}

func (f *fakeGovStore) TenantPolicy(_ context.Context, tenantID string) (govern.Policy, bool, error) {
	p, ok := f.policies[tenantID]
	return p, ok, nil
}

func (f *fakeGovStore) SetTenantPolicy(_ context.Context, tenantID string, pol govern.Policy, _ string, auditTx func(context.Context, tenancy.Scope) error) error {
	// Mirror the real store's fail-closed contract: a governance policy change
	// must carry a tenant audit receipt (G7-7). If the handler ever stopped
	// wiring one, the write is refused here — which is what the audit-wiring
	// assertion below depends on.
	if auditTx == nil {
		return govern.ErrAuditReceiptRequired
	}
	f.auditProvided = true
	f.lastSetTenant = tenantID
	f.lastSetPol = pol
	f.setN++
	if f.policies == nil {
		f.policies = map[string]govern.Policy{}
	}
	f.policies[tenantID] = pol
	return nil
}

const otherTenantID = "11111111-1111-1111-1111-111111111111"

// TestGovernancePolicyHiddenUnlicensed: with no governance store installed (the
// `governance` feature is not licensed / core build), both routes 404 — hidden,
// not lockware.
func TestGovernancePolicyHiddenUnlicensed(t *testing.T) {
	srv := testServer(nil)
	for _, tc := range []struct{ method, body string }{
		{http.MethodGet, ""},
		{http.MethodPut, `{"ai_remote_egress":true}`},
	} {
		rr := httptest.NewRecorder()
		var r *http.Request
		if tc.body == "" {
			r = httptest.NewRequest(tc.method, "/v1/governance/policy", nil)
		} else {
			r = httptest.NewRequest(tc.method, "/v1/governance/policy", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
		}
		srv.Handler().ServeHTTP(rr, r)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s unlicensed: status %d, want 404 (hidden)", tc.method, rr.Code)
		}
	}
}

// TestGovernancePolicyTenantScopedReadWrite: with the store installed (licensed
// Enterprise seam) a tenant admin reads and updates its OWN policy. The read is
// scoped to the tenant in the authenticated principal (two tenants see two
// policies), the update records the tenant-from-context and wires a tenant audit
// receipt, and a following read reflects the written consent.
func TestGovernancePolicyTenantScopedReadWrite(t *testing.T) {
	fake := &fakeGovStore{policies: map[string]govern.Policy{
		tenancy.DefaultTenantID.String(): {AIRemoteEgress: false},
		otherTenantID:                    {AIRemoteEgress: true},
	}}
	srv := testServer(nil)
	srv.WithGovernance(fake)

	// Read is tenant-scoped: each tenant sees only its own consent.
	if got := getEgress(t, srv, tenancy.DefaultTenantID.String()); got {
		t.Fatalf("default tenant GET ai_remote_egress = true, want false")
	}
	if got := getEgress(t, srv, otherTenantID); !got {
		t.Fatalf("other tenant GET ai_remote_egress = false, want true")
	}

	// Update the default tenant's consent to true. The body carries no tenant
	// field by construction (G7-1): the tenant is the authenticated principal's.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/v1/governance/policy", strings.NewReader(`{"ai_remote_egress":true,"redact_export":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Probectl-Tenant", tenancy.DefaultTenantID.String())
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rr.Code, rr.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode PUT response: %v (%s)", err, rr.Body)
	}
	if out["ai_remote_egress"] != true {
		t.Fatalf("PUT response ai_remote_egress = %v, want true", out["ai_remote_egress"])
	}
	// The store received the tenant from context, the new consent, and a receipt.
	if fake.lastSetTenant != tenancy.DefaultTenantID.String() {
		t.Fatalf("store wrote tenant %q, want the principal's tenant %q", fake.lastSetTenant, tenancy.DefaultTenantID)
	}
	if !fake.lastSetPol.AIRemoteEgress {
		t.Fatalf("store wrote ai_remote_egress=false, want true")
	}
	if !fake.auditProvided {
		t.Fatalf("handler did not wire a tenant audit receipt for the governance change (G7-7)")
	}

	// The write took: a following read reflects the new consent, and the OTHER
	// tenant's policy is untouched.
	if got := getEgress(t, srv, tenancy.DefaultTenantID.String()); !got {
		t.Fatalf("after PUT, default tenant GET ai_remote_egress = false, want true")
	}
	if got := getEgress(t, srv, otherTenantID); !got {
		t.Fatalf("other tenant policy changed under a default-tenant PUT (isolation)")
	}
}

// TestGovernancePolicyRBAC: GET needs governance.read, PUT needs
// governance.write. Dropping the permission for one request yields 403, proving
// the surface is RBAC-gated to the tenant-admin role, not merely authenticated.
func TestGovernancePolicyRBAC(t *testing.T) {
	fake := &fakeGovStore{policies: map[string]govern.Policy{tenancy.DefaultTenantID.String(): {}}}
	srv := testServer(nil)
	srv.WithGovernance(fake)

	for _, tc := range []struct {
		name, method, withhold, body string
	}{
		{"read denied", http.MethodGet, "governance.read", ""},
		{"write denied", http.MethodPut, "governance.write", `{"ai_remote_egress":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			var r *http.Request
			if tc.body == "" {
				r = httptest.NewRequest(tc.method, "/v1/governance/policy", nil)
			} else {
				r = httptest.NewRequest(tc.method, "/v1/governance/policy", strings.NewReader(tc.body))
				r.Header.Set("Content-Type", "application/json")
			}
			r.Header.Set(testWithholdPermissionsHeader, tc.withhold)
			srv.Handler().ServeHTTP(rr, r)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("%s without %s: status %d, want 403", tc.method, tc.withhold, rr.Code)
			}
		})
	}
}

// TestGovernancePolicyReadOnlyLicenseRefusesEditsButNotConsentWithdrawal: on a
// read-only license (the store wrapped in govern.GatePolicyWrites, exactly as
// the attach seam wires it) the policy stays readable, an edit is a 403
// license_read_only that never reaches the store, and withdrawing the remote-AI
// egress consent still goes through.
func TestGovernancePolicyReadOnlyLicenseRefusesEditsButNotConsentWithdrawal(t *testing.T) {
	fake := &fakeGovStore{policies: map[string]govern.Policy{tenancy.DefaultTenantID.String(): {AIRemoteEgress: true}}}
	srv := testServer(nil)
	srv.WithGovernance(govern.GatePolicyWrites(fake, func() bool { return false }))
	put := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/v1/governance/policy", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Probectl-Tenant", tenancy.DefaultTenantID.String())
		srv.Handler().ServeHTTP(rr, req)
		return rr
	}

	if rr := put(`{"ai_remote_egress":true,"redact_export":true}`); rr.Code != http.StatusForbidden ||
		!strings.Contains(rr.Body.String(), "license_read_only") || fake.setN != 0 {
		t.Fatalf("edit on a read-only license = %d %s (store writes %d), want 403 license_read_only before the store", rr.Code, rr.Body, fake.setN)
	}
	if !getEgress(t, srv, tenancy.DefaultTenantID.String()) {
		t.Fatal("the policy must stay readable on a read-only license")
	}
	if rr := put(`{"ai_remote_egress":false}`); rr.Code != http.StatusOK || fake.setN != 1 {
		t.Fatalf("consent withdrawal on a read-only license = %d %s (store writes %d), want 200", rr.Code, rr.Body, fake.setN)
	}
	if getEgress(t, srv, tenancy.DefaultTenantID.String()) {
		t.Fatal("the withdrawn consent did not take")
	}
}

func getEgress(t *testing.T, srv *Server, tenant string) bool {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/governance/policy", nil)
	req.Header.Set("X-Probectl-Tenant", tenant)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", tenant, rr.Code, rr.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode GET response: %v (%s)", err, rr.Body)
	}
	v, ok := out["ai_remote_egress"].(bool)
	if !ok {
		t.Fatalf("GET response missing bool ai_remote_egress: %s", rr.Body)
	}
	return v
}
