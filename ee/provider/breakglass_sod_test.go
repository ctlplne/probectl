// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/license"
)

// memTenantAudit captures the tenant-stream events TenantRevoke writes so the
// unit test can prove a tenant-side revoke lands on the tenant's OWN chain as
// well as the provider break-glass stream (AUD-13 / docs/guardrails.md G7-7).
type memTenantAudit struct {
	mu     sync.Mutex
	events []tenantAuditEvent
}

type tenantAuditEvent struct {
	TenantID, Actor, Action, Target string
	Data                            map[string]any
}

func (a *memTenantAudit) AppendTenantAudit(_ context.Context, tenantID, actor, action, target string, data map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, tenantAuditEvent{
		TenantID: tenantID, Actor: actor, Action: action, Target: target, Data: data,
	})
	return nil
}

func (a *memTenantAudit) count(tenantID, action string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.events {
		if e.TenantID == tenantID && e.Action == action {
			n++
		}
	}
	return n
}

// TestAudlogBreakGlassSelfConsentAndTenantRevoke is the AUD-13 regression: a
// provider operator cannot approve their own break-glass request from a
// tenant-admin account that shares their verified identity (separation of
// duties), and a tenant admin can revoke a grant it consented to — recorded on
// both the provider and tenant audit streams — which immediately ends the
// operator's telemetry read. The operator's own revoke route is unchanged.
func TestAudlogBreakGlassSelfConsentAndTenantRevoke(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	tenantAudit := &memTenantAudit{}
	f.svc.WithTenantAudit(tenantAudit)
	f.svc.telemetry = fakeTelemetry{byTenant: map[string][]string{"tnA": {"result-A1"}}}

	// The provider operator is root@msp.example.
	operatorToken := f.bootstrapAndLoginFast(t)

	// The SAME person also holds a tenant-admin account in tenant A: a tenant
	// session whose verified email equals the operator's (the finding's A1b).
	f.tenantAuth.sessions["tenant-root-self"] = &auth.Session{
		ID: "sRoot", TenantID: "tnA", UserID: "uRoot", Email: "root@msp.example",
	}
	f.tenantAuth.perms["uRoot"] = []string{"directory.read", "directory.write"}

	// A DIFFERENT provider operator, plus a tenant-admin account sharing that
	// operator's email — to prove "or any provider operator".
	rec := f.doAuthed(t, operatorToken, http.MethodPost, "/provider/v1/operators",
		map[string]string{"email": "op2@msp.example", "name": "Op Two", "role": "operator"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create second operator: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Operator Operator `json:"operator"`
	}
	mustDecode(t, rec, &created)
	f.activateAndIssue(t, created.Operator) // the operator is now on the roster
	f.tenantAuth.sessions["tenant-op2-self"] = &auth.Session{
		ID: "sOp2", TenantID: "tnA", UserID: "uOp2", Email: "op2@msp.example",
	}
	f.tenantAuth.perms["uOp2"] = []string{"directory.read", "directory.write"}

	requestGrant := func(reason string) Grant {
		t.Helper()
		rec := f.doAuthed(t, operatorToken, http.MethodPost, "/provider/v1/breakglass",
			map[string]any{"tenant_id": "tnA", "reason": reason, "ttl_minutes": 60})
		if rec.Code != http.StatusCreated {
			t.Fatalf("request grant: %d %s", rec.Code, rec.Body.String())
		}
		var g Grant
		mustDecode(t, rec, &g)
		return g
	}
	consent := func(session, grantID string) *httptest.ResponseRecorder {
		req := newReq(http.MethodPost, "/provider/v1/consent/"+grantID, map[string]string{"decision": "approve"})
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: session})
		return doReq(f.h, req)
	}
	tenantRevoke := func(session, grantID string) *httptest.ResponseRecorder {
		req := newReq(http.MethodPost, "/provider/v1/consent/"+grantID+"/revoke", nil)
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: session})
		return doReq(f.h, req)
	}
	results := func(grantID string) *httptest.ResponseRecorder {
		return f.doAuthed(t, operatorToken, http.MethodGet, "/provider/v1/breakglass/"+grantID+"/results", nil)
	}

	// --- A1: self-consent is refused (separation of duties) ---
	g := requestGrant("incident #42: self-consent attempt")

	if rec := consent("tenant-root-self", g.ID); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "separation_of_duties") {
		t.Fatalf("self-consent (same identity as the requesting operator) must be 403 separation_of_duties, got %d %s",
			rec.Code, rec.Body.String())
	}
	// It did not activate the grant: the operator still cannot read.
	if rec := results(g.ID); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "breakglass_not_active") {
		t.Fatalf("a refused self-consent must not unlock telemetry, got %d %s", rec.Code, rec.Body.String())
	}
	// ANY provider operator's identity is equally refused.
	if rec := consent("tenant-op2-self", g.ID); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "separation_of_duties") {
		t.Fatalf("consent by another provider operator's identity must be 403, got %d %s", rec.Code, rec.Body.String())
	}

	// A genuinely independent tenant admin CAN consent (the cross-identity case).
	if rec := consent("tenant-admin-A", g.ID); rec.Code != http.StatusOK {
		t.Fatalf("independent tenant admin consent must be 200, got %d %s", rec.Code, rec.Body.String())
	}
	// Now active: the operator can read.
	if rec := results(g.ID); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "result-A1") {
		t.Fatalf("active grant must read tenant A telemetry, got %d %s", rec.Code, rec.Body.String())
	}

	// --- A2: the tenant revokes the ACTIVE grant via its own route ---
	beforeProvider := f.audit.count("provider.breakglass_revoke")
	if rec := tenantRevoke("tenant-admin-A", g.ID); rec.Code != http.StatusOK {
		t.Fatalf("tenant revoke of an active grant must be 200, got %d %s", rec.Code, rec.Body.String())
	}
	// The operator's read now takes the not-active path, immediately.
	if rec := results(g.ID); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "breakglass_not_active") {
		t.Fatalf("after tenant revoke the operator read must be 403 breakglass_not_active, got %d %s",
			rec.Code, rec.Body.String())
	}
	// Recorded on BOTH streams (G7-7).
	if got := f.audit.count("provider.breakglass_revoke"); got != beforeProvider+1 {
		t.Fatalf("tenant revoke must be recorded on the provider stream: count delta = %d, want 1", got-beforeProvider)
	}
	if got := tenantAudit.count("tnA", "breakglass.revoke"); got != 1 {
		t.Fatalf("tenant revoke must be recorded on the tenant's own audit chain: got %d, want 1", got)
	}

	// --- the tenant boundary still holds on the revoke route ---
	g2 := requestGrant("incident #43: cross-tenant revoke attempt")
	if rec := consent("tenant-admin-A", g2.ID); rec.Code != http.StatusOK {
		t.Fatalf("consent g2: %d %s", rec.Code, rec.Body.String())
	}
	if rec := tenantRevoke("tenant-admin-B", g2.ID); rec.Code != http.StatusForbidden {
		t.Fatalf("a different tenant must not revoke tenant A's grant, got %d %s", rec.Code, rec.Body.String())
	}
	// Tenant B's failed attempt left the grant usable.
	if rec := results(g2.ID); rec.Code != http.StatusOK {
		t.Fatalf("cross-tenant revoke must not affect the grant, got %d %s", rec.Code, rec.Body.String())
	}

	// --- the OPERATOR revoke route is unchanged ---
	if rec := f.doAuthed(t, operatorToken, http.MethodPost, "/provider/v1/breakglass/"+g2.ID+"/revoke", nil); rec.Code != http.StatusOK {
		t.Fatalf("operator revoke route must still work, got %d %s", rec.Code, rec.Body.String())
	}
	if rec := results(g2.ID); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "breakglass_not_active") {
		t.Fatalf("after operator revoke the read must be 403 breakglass_not_active, got %d %s", rec.Code, rec.Body.String())
	}
}
