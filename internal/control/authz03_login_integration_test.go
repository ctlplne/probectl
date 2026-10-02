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

// TestCallbackBindsStableIssuerSubject is the AUTHZ-03 end-to-end regression,
// driven through the real /auth/login + /auth/callback entry points:
//
//	(a) an ID token the IdP reports email_verified=false -> 401;
//	(b) a second subject presenting the same email after the first binding -> 401;
//	(c) a pre-created (SCIM) account links to its first (iss, sub) exactly once
//	    and is thereafter matched only by that pair.
func TestCallbackBindsStableIssuerSubject(t *testing.T) {
	boolp := func(b bool) *bool { return &b }
	const issuer = "https://idp.authz03.example"
	verifiedTrue := boolp(true)

	ident := auth.Identity{
		Issuer:        issuer,
		Subject:       fmt.Sprintf("authz03-subA-%d", time.Now().UnixNano()),
		Email:         fmt.Sprintf("authz03-jit-%d@example.com", time.Now().UnixNano()),
		DisplayName:   "AuthZ03 JIT User",
		EmailVerified: verifiedTrue,
	}
	srv, db, provider := setupSessionAPIWithProvider(t, ident)
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
	callback := func(code string) *httptest.ResponseRecorder {
		st, tn, nc, pk := login()
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code="+code+"&state="+st.Value, nil)
		for _, c := range []*http.Cookie{st, tn, nc, pk} {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// First login: JIT-provision + bind (iss, subA). A session is minted.
	if cb := callback("c1"); cb.Code != http.StatusFound || findCookie(cb.Result().Cookies(), auth.SessionCookie) == nil {
		t.Fatalf("first login: want 302 + session, got %d: %s", cb.Code, cb.Body)
	}
	// The account carries the binding and is matched by it, not by email alone.
	assertBoundTo(t, db, ident.Email, issuer, ident.Subject)

	// (c) A second login with the SAME (iss, subA) matches the binding -> 302.
	if cb := callback("c2"); cb.Code != http.StatusFound {
		t.Fatalf("repeat login with same (iss,sub): want 302, got %d: %s", cb.Code, cb.Body)
	}

	// (b) A DIFFERENT subject presenting the SAME email is refused -> 401, and
	// the stored binding is untouched (no silent takeover).
	provider.ident.Subject = fmt.Sprintf("authz03-subB-%d", time.Now().UnixNano())
	if cb := callback("c3"); cb.Code != http.StatusUnauthorized {
		t.Fatalf("second subject, same email: want 401, got %d: %s", cb.Code, cb.Body)
	}
	if findCookie(callback("c3b").Result().Cookies(), auth.SessionCookie) != nil {
		t.Fatal("a session was minted for a second subject claiming a bound email")
	}
	assertBoundTo(t, db, ident.Email, issuer, ident.Subject) // still subA

	// (a) email_verified=false is refused -> 401, even for the bound subject.
	provider.ident.Subject = ident.Subject // back to the legitimate subject
	provider.ident.EmailVerified = boolp(false)
	if cb := callback("c4"); cb.Code != http.StatusUnauthorized {
		t.Fatalf("email_verified=false: want 401, got %d: %s", cb.Code, cb.Body)
	}
	provider.ident.EmailVerified = verifiedTrue

	// (c) Pre-created (SCIM) account: an email row with no binding links to its
	// first OIDC subject exactly once, then is matched only by that pair.
	preEmail := fmt.Sprintf("authz03-pre-%d@example.com", time.Now().UnixNano())
	subC := fmt.Sprintf("authz03-subC-%d", time.Now().UnixNano())
	preProvision(t, db, preEmail)
	provider.ident.Email = preEmail
	provider.ident.Subject = subC
	if cb := callback("c5"); cb.Code != http.StatusFound {
		t.Fatalf("pre-created first login: want 302 (link), got %d: %s", cb.Code, cb.Body)
	}
	assertBoundTo(t, db, preEmail, issuer, subC)

	// A different subject reusing the now-linked email is refused -> 401.
	provider.ident.Subject = fmt.Sprintf("authz03-subD-%d", time.Now().UnixNano())
	if cb := callback("c6"); cb.Code != http.StatusUnauthorized {
		t.Fatalf("second subject on linked pre-created account: want 401, got %d: %s", cb.Code, cb.Body)
	}
	assertBoundTo(t, db, preEmail, issuer, subC) // still subC
}

func preProvision(t *testing.T, db *store.DB, email string) {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.DefaultTenantID)
	if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, e := (store.Users{}).Create(ctx, sc, email, "Pre-created")
		return e
	}); err != nil {
		t.Fatalf("pre-provision %s: %v", email, err)
	}
}

func assertBoundTo(t *testing.T, db *store.DB, email, issuer, subject string) {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.DefaultTenantID)
	if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		u, e := (store.Users{}).GetByEmail(ctx, sc, email)
		if e != nil {
			return e
		}
		if u.OIDCIssuer != issuer || u.OIDCSubject != subject {
			return fmt.Errorf("binding = (%q,%q), want (%q,%q)", u.OIDCIssuer, u.OIDCSubject, issuer, subject)
		}
		bound, e := (store.Users{}).GetByOIDC(ctx, sc, issuer, subject)
		if e != nil {
			return fmt.Errorf("GetByOIDC: %w", e)
		}
		if bound.ID != u.ID {
			return fmt.Errorf("GetByOIDC returned %s, want %s", bound.ID, u.ID)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
