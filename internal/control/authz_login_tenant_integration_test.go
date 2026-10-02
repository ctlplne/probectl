// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestCallbackBlocksJITViaFallbackIdPInMultiTenant is the AUTHZ-06 regression.
// In a multi-tenant profile, a deployment/fallback-IdP identity that is not
// provisioned in the target tenant must be refused at the callback (no session,
// no user row) — otherwise every user of the shared IdP could join any tenant
// without its own IdP. A pre-provisioned identity still logs in, and /v1/me for
// a role-less user omits the tenant name/slug (no tenant-name enumeration).
func TestCallbackBlocksJITViaFallbackIdPInMultiTenant(t *testing.T) {
	ident := auth.Identity{
		Subject:     fmt.Sprintf("authz06-sub-%d", time.Now().UnixNano()),
		Email:       fmt.Sprintf("authz06-%d@example.com", time.Now().UnixNano()),
		DisplayName: "AuthZ06 User",
	}
	srv, db, _ := setupSessionAPIWithProvider(t, ident)
	// Multi-tenant profile + the fake factory (no SourceFor) models a login via
	// the deployment fallback IdP rather than a tenant's own IdP.
	srv.cfg.DeploymentProfile = "multi-tenant"
	h := srv.Handler()

	login := func() (state, tenant, nonce, pkce *http.Cookie) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("login: want 302, got %d: %s", rec.Code, rec.Body)
		}
		cs := rec.Result().Cookies()
		return findCookie(cs, oauthStateCookie), findCookie(cs, oauthTenantCookie),
			findCookie(cs, oauthNonceCookie), findCookie(cs, oauthPKCECookie)
	}
	callback := func(code string, cks ...*http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code="+code+"&state="+cks[0].Value, nil)
		for _, c := range cks {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 1. Unprovisioned identity via the fallback IdP -> refused, no session.
	st, tn, nc, pk := login()
	cb := callback("abc", st, tn, nc, pk)
	if cb.Code != http.StatusForbidden {
		t.Fatalf("unprovisioned fallback-IdP callback = %d, want 403 (JIT via fallback IdP must be refused in multi-tenant): %s", cb.Code, cb.Body)
	}
	if findCookie(cb.Result().Cookies(), auth.SessionCookie) != nil {
		t.Fatal("a session cookie was minted for an unprovisioned identity")
	}
	tenantID := tn.Value
	// ... and NO user row was created in the tenant.
	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenantID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		if _, e := (store.Users{}).GetByEmail(ctx, sc, ident.Email); e == nil {
			return fmt.Errorf("a user row was JIT-created for the unprovisioned identity")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// 2. Pre-provision the identity; the same login now succeeds.
	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenantID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, e := (store.Users{}).Create(ctx, sc, ident.Email, ident.DisplayName)
		return e
	}); err != nil {
		t.Fatalf("pre-provision: %v", err)
	}
	st2, tn2, nc2, pk2 := login()
	cb2 := callback("def", st2, tn2, nc2, pk2)
	if cb2.Code != http.StatusFound {
		t.Fatalf("provisioned identity callback = %d, want 302: %s", cb2.Code, cb2.Body)
	}
	sess := findCookie(cb2.Result().Cookies(), auth.SessionCookie)
	if sess == nil || sess.Value == "" {
		t.Fatal("provisioned login did not mint a session")
	}

	// 3. /v1/me for the role-less user: tenant_id present, tenant name/slug omitted.
	me := withCookie(t, h, http.MethodGet, "/v1/me", sess)
	if me.Code != http.StatusOK {
		t.Fatalf("/v1/me = %d, want 200: %s", me.Code, me.Body)
	}
	var body struct {
		TenantID    string   `json:"tenant_id"`
		TenantName  string   `json:"tenant_name"`
		TenantSlug  string   `json:"tenant_slug"`
		Permissions []string `json:"permissions"`
	}
	mustDecode(t, me, &body)
	if len(body.Permissions) != 0 {
		t.Fatalf("expected a role-less user, got permissions %v", body.Permissions)
	}
	if body.TenantID == "" {
		t.Error("/v1/me omitted tenant_id (the user's own id is theirs to see)")
	}
	if body.TenantName != "" || body.TenantSlug != "" {
		t.Fatalf("/v1/me disclosed tenant name/slug to a role-less user: name=%q slug=%q (AUTHZ-06)", body.TenantName, body.TenantSlug)
	}
}
