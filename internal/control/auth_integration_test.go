// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/migrations"
)

// fakeProvider is a stand-in OIDC provider returning a fixed identity — it lets
// the full login flow (state cookie → callback → JIT provisioning → session) run
// without a real IdP or network. The real OIDC path is covered by the auth
// package's mock-IdP test.
type fakeProvider struct {
	ident auth.Identity
	// echoNonce mimics a correct IdP: the nonce sent at AuthCodeURL comes
	// back as the ID token's nonce claim (SEC-004). wrongNonce simulates a
	// replayed/substituted token.
	lastNonce  string
	lastPKCE   string
	wrongNonce bool
}

func (f *fakeProvider) AuthCodeURL(state, nonce, codeVerifier string) string {
	f.lastNonce = nonce
	f.lastPKCE = codeVerifier
	return "https://idp.example/authorize?state=" + state
}

func (f *fakeProvider) Exchange(_ context.Context, _, codeVerifier string) (*auth.Identity, error) {
	if codeVerifier == "" || codeVerifier != f.lastPKCE {
		return nil, fmt.Errorf("PKCE verifier mismatch")
	}
	id := f.ident
	id.Nonce = f.lastNonce
	if f.wrongNonce {
		id.Nonce = "replayed-token-nonce"
	}
	return &id, nil
}

type fakeFactory struct{ p auth.Provider }

func (f fakeFactory) For(context.Context, string) (auth.Provider, error) { return f.p, nil }

func setupSessionAPI(t *testing.T, ident auth.Identity) (*Server, *store.DB) {
	t.Helper()
	srv, db, _ := setupSessionAPIWithProvider(t, ident)
	return srv, db
}

func setupSessionAPIWithProvider(t *testing.T, ident auth.Identity) (*Server, *store.DB, *fakeProvider) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, integrationDSN(), 5, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		t.Skipf("no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		db.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	t.Cleanup(db.Close)
	cfg := &config.Config{HSTSEnabled: true, HSTSMaxAge: time.Hour, AuthMode: "session", SessionTTL: time.Hour}
	srv := New(cfg, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil)
	provider := &fakeProvider{ident: ident}
	srv.SetSSOProviderFactory(fakeFactory{p: provider})
	return srv, db, provider
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func withCookie(t *testing.T, h http.Handler, method, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// bindRole binds a seeded system role (by slug) to a user in the default tenant.
func bindRole(t *testing.T, db *store.DB, userID, slug string) {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.DefaultTenantID)
	err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		var roleID string
		if err := sc.Q.QueryRow(ctx, `SELECT id::text FROM roles WHERE slug=$1`, slug).Scan(&roleID); err != nil {
			return err
		}
		_, err := store.RoleBindings{}.Create(ctx, sc, "user", userID, roleID, "tenant", nil)
		return err
	})
	if err != nil {
		t.Fatalf("bind role %s: %v", slug, err)
	}
}

// TestSSOLoginAndRBAC drives the whole S18 acceptance path: an SSO login mints a
// session; a just-provisioned user has NO roles and is denied; after binding the
// viewer role, reads are allowed but writes are still denied (403). Permissions
// are loaded per request, so the role grant takes effect on the live session.
func TestSSOLoginAndRBAC(t *testing.T) {
	// Unique email per run so the test is re-runnable against a persistent DB
	// (a fresh SSO user must start with no roles).
	ident := auth.Identity{
		Subject:     fmt.Sprintf("sub-%d", time.Now().UnixNano()),
		Email:       fmt.Sprintf("sso-user-%d@example.com", time.Now().UnixNano()),
		DisplayName: "SSO User",
		TimeZone:    "Asia/Tokyo",
		Locale:      "ar-EG",
	}
	srv, db, provider := setupSessionAPIWithProvider(t, ident)
	h := srv.Handler()

	// 1. Begin login → 302 + transient state/tenant cookies.
	login := httptest.NewRecorder()
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if login.Code != http.StatusFound {
		t.Fatalf("login: want 302, got %d: %s", login.Code, login.Body)
	}
	state := findCookie(login.Result().Cookies(), oauthStateCookie)
	tenantCk := findCookie(login.Result().Cookies(), oauthTenantCookie)
	nonceCk := findCookie(login.Result().Cookies(), oauthNonceCookie)
	pkceCk := findCookie(login.Result().Cookies(), oauthPKCECookie)
	if state == nil || state.Value == "" {
		t.Fatal("login did not set the oauth state cookie")
	}
	if nonceCk == nil || nonceCk.Value == "" {
		t.Fatal("login did not set the oauth nonce cookie (SEC-004)")
	}
	if pkceCk == nil || len(pkceCk.Value) < 43 || !pkceCk.HttpOnly {
		t.Fatalf("login did not set a conforming HttpOnly PKCE verifier cookie: %+v", pkceCk)
	}

	// 2. Callback with matching state + nonce → 302 + session cookie.
	cb := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+state.Value, nil)
	cb.AddCookie(state)
	cb.AddCookie(tenantCk)
	cb.AddCookie(nonceCk)
	cb.AddCookie(pkceCk)
	cbRec := httptest.NewRecorder()
	h.ServeHTTP(cbRec, cb)
	if cbRec.Code != http.StatusFound {
		t.Fatalf("callback: want 302, got %d: %s", cbRec.Code, cbRec.Body)
	}
	sess := findCookie(cbRec.Result().Cookies(), auth.SessionCookie)
	if sess == nil || sess.Value == "" {
		t.Fatal("callback did not set a session cookie")
	}
	if !sess.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	clearedPKCE := findCookie(cbRec.Result().Cookies(), oauthPKCECookie)
	if clearedPKCE == nil || clearedPKCE.MaxAge >= 0 {
		t.Fatalf("callback did not expire one-time PKCE verifier: %+v", clearedPKCE)
	}

	// The second IdP proof changes MFA and user preferences. Login replacement
	// must adopt these fresh assertions; ordinary permission rotation would
	// intentionally preserve the old session values.
	provider.ident.MFASatisfied = true
	provider.ident.TimeZone = "America/New_York"
	provider.ident.Locale = "fr"

	// A second successful login in the same browser must consume the first
	// session ID and return a distinct token (session-fixation defense).
	login2Req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	login2Req.AddCookie(sess)
	login2 := httptest.NewRecorder()
	h.ServeHTTP(login2, login2Req)
	state2 := findCookie(login2.Result().Cookies(), oauthStateCookie)
	tenant2 := findCookie(login2.Result().Cookies(), oauthTenantCookie)
	nonce2 := findCookie(login2.Result().Cookies(), oauthNonceCookie)
	pkce2 := findCookie(login2.Result().Cookies(), oauthPKCECookie)
	cb2 := httptest.NewRequest(http.MethodGet, "/auth/callback?code=def&state="+state2.Value, nil)
	for _, c := range []*http.Cookie{sess, state2, tenant2, nonce2, pkce2} {
		cb2.AddCookie(c)
	}
	cb2Rec := httptest.NewRecorder()
	h.ServeHTTP(cb2Rec, cb2)
	rotated := findCookie(cb2Rec.Result().Cookies(), auth.SessionCookie)
	if cb2Rec.Code != http.StatusFound || rotated == nil || rotated.Value == "" || rotated.Value == sess.Value {
		t.Fatalf("repeat login did not rotate session: code=%d old=%v new=%v", cb2Rec.Code, sess, rotated)
	}
	if rec := withCookie(t, h, http.MethodGet, "/v1/me", sess); rec.Code != http.StatusUnauthorized {
		t.Fatalf("pre-login token survived rotation: want 401, got %d", rec.Code)
	}
	sess = rotated

	// 3. /v1/me with the session → 200; the JIT-provisioned user has no roles.
	me := withCookie(t, h, http.MethodGet, "/v1/me", sess)
	if me.Code != http.StatusOK {
		t.Fatalf("me: want 200, got %d: %s", me.Code, me.Body)
	}
	var meBody struct {
		UserID         string   `json:"user_id"`
		Email          string   `json:"email"`
		TimeZone       string   `json:"time_zone"`
		Locale         string   `json:"locale"`
		TenantTimeZone string   `json:"tenant_time_zone"`
		TenantLocale   string   `json:"tenant_locale"`
		MFASatisfied   bool     `json:"mfa_satisfied"`
		Permissions    []string `json:"permissions"`
	}
	mustDecode(t, me, &meBody)
	if meBody.Email != ident.Email {
		t.Fatalf("me email = %s", meBody.Email)
	}
	if meBody.TimeZone != "America/New_York" || meBody.Locale != "fr" {
		t.Fatalf("me user prefs = timezone:%q locale:%q", meBody.TimeZone, meBody.Locale)
	}
	if !meBody.MFASatisfied {
		t.Fatal("repeat login did not adopt the fresh IdP MFA assertion")
	}
	if meBody.TenantTimeZone != "UTC" || meBody.TenantLocale != "en" {
		t.Fatalf("me tenant prefs = timezone:%q locale:%q", meBody.TenantTimeZone, meBody.TenantLocale)
	}
	if len(meBody.Permissions) != 0 {
		t.Fatalf("a new SSO user must have no roles, got %v", meBody.Permissions)
	}

	// 4. With no role, a scoped read is denied (403) — authenticated but not
	// authorized.
	if rec := withCookie(t, h, http.MethodGet, "/v1/tests", sess); rec.Code != http.StatusForbidden {
		t.Fatalf("no-role read: want 403, got %d", rec.Code)
	}

	// 5. Grant viewer → reads allowed, writes still denied (403). RBAC is checked
	// before the handler, so the missing body never matters. The first request
	// after the grant rotates the session ID before serving elevated access.
	bindRole(t, db, meBody.UserID, "viewer")
	viewerRead := withCookie(t, h, http.MethodGet, "/v1/tests", sess)
	if viewerRead.Code != http.StatusOK {
		t.Fatalf("viewer read: want 200, got %d: %s", viewerRead.Code, viewerRead.Body)
	}
	elevated := findCookie(viewerRead.Result().Cookies(), auth.SessionCookie)
	if elevated == nil || elevated.Value == "" || elevated.Value == sess.Value {
		t.Fatalf("role elevation did not rotate session: old=%v new=%v", sess, elevated)
	}
	sess = elevated
	if rec := withCookie(t, h, http.MethodPost, "/v1/tests", sess); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer write: want 403, got %d: %s", rec.Code, rec.Body)
	}

	// 6. Logout revokes the session; the cookie no longer authenticates.
	logout := withCookie(t, h, http.MethodPost, "/auth/logout", sess)
	if logout.Code != http.StatusNoContent {
		t.Fatalf("logout: want 204, got %d", logout.Code)
	}
	if rec := withCookie(t, h, http.MethodGet, "/v1/me", sess); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after logout: want 401, got %d", rec.Code)
	}
}

func TestBearerTokenAuthenticatesTenantAPI(t *testing.T) {
	srv, db := setupSessionAPI(t, auth.Identity{})
	h := srv.Handler()
	tenant := freshTenant(t, db, "bearer")
	other := freshTenant(t, db, "bearer-other")
	userID := createUserWithPerm(t, db, tenant, "api-bearer@example.com", nil, permTestRead)
	token, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewMCPTokens(db.Pool()).Create(context.Background(), tenant, userID, "first-api-smoke", crypto.Hash([]byte(token))); err != nil {
		t.Fatalf("create bearer token: %v", err)
	}

	meReq := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+token)
	meReq.Header.Set("X-Probectl-Tenant", tenant)
	me := httptest.NewRecorder()
	h.ServeHTTP(me, meReq)
	if me.Code != http.StatusOK {
		t.Fatalf("bearer /v1/me: want 200, got %d: %s", me.Code, me.Body)
	}
	var meBody struct {
		TenantID string `json:"tenant_id"`
		UserID   string `json:"user_id"`
		Email    string `json:"email"`
	}
	mustDecode(t, me, &meBody)
	if meBody.TenantID != tenant || meBody.UserID != userID || meBody.Email != "api-bearer@example.com" {
		t.Fatalf("bearer principal = %+v, want tenant=%s user=%s email", meBody, tenant, userID)
	}

	testsReq := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
	testsReq.Header.Set("Authorization", "Bearer "+token)
	testsReq.Header.Set("X-Probectl-Tenant", tenant)
	tests := httptest.NewRecorder()
	h.ServeHTTP(tests, testsReq)
	if tests.Code != http.StatusOK {
		t.Fatalf("bearer /v1/tests: want 200, got %d: %s", tests.Code, tests.Body)
	}

	mismatchReq := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
	mismatchReq.Header.Set("Authorization", "Bearer "+token)
	mismatchReq.Header.Set("X-Probectl-Tenant", other)
	mismatch := httptest.NewRecorder()
	h.ServeHTTP(mismatch, mismatchReq)
	if mismatch.Code != http.StatusUnauthorized || !strings.Contains(mismatch.Body.String(), "authentication required") {
		t.Fatalf("mismatched tenant assertion: want 401 authentication required, got %d: %s", mismatch.Code, mismatch.Body)
	}
}

// SEC-004: a callback whose ID token carries a DIFFERENT nonce than the one
// minted at login is rejected — replayed/substituted tokens fail closed.
func TestCallbackRejectsNonceMismatch(t *testing.T) {
	srv, _ := setupSessionAPI(t, auth.Identity{Email: "nonce@example.com"})
	evil := &fakeProvider{ident: auth.Identity{Email: "nonce@example.com"}, wrongNonce: true}
	srv.SetSSOProviderFactory(fakeFactory{p: evil})
	h := srv.Handler()

	login := httptest.NewRecorder()
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	state := findCookie(login.Result().Cookies(), oauthStateCookie)
	tenantCk := findCookie(login.Result().Cookies(), oauthTenantCookie)
	nonceCk := findCookie(login.Result().Cookies(), oauthNonceCookie)
	pkceCk := findCookie(login.Result().Cookies(), oauthPKCECookie)

	cb := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+state.Value, nil)
	cb.AddCookie(state)
	cb.AddCookie(tenantCk)
	cb.AddCookie(nonceCk)
	cb.AddCookie(pkceCk)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, cb)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("nonce mismatch must be 401, got %d: %s", rec.Code, rec.Body)
	}
	if findCookie(rec.Result().Cookies(), auth.SessionCookie) != nil {
		t.Fatal("nonce mismatch must not mint a session")
	}
}

// SEC-004: a callback MISSING the nonce cookie is rejected outright.
func TestCallbackRejectsMissingNonceCookie(t *testing.T) {
	srv, _ := setupSessionAPI(t, auth.Identity{Email: "nonce2@example.com"})
	h := srv.Handler()

	login := httptest.NewRecorder()
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	state := findCookie(login.Result().Cookies(), oauthStateCookie)
	tenantCk := findCookie(login.Result().Cookies(), oauthTenantCookie)
	pkceCk := findCookie(login.Result().Cookies(), oauthPKCECookie)

	cb := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+state.Value, nil)
	cb.AddCookie(state)
	cb.AddCookie(tenantCk) // nonce cookie deliberately omitted
	cb.AddCookie(pkceCk)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, cb)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing nonce cookie must be 401, got %d: %s", rec.Code, rec.Body)
	}
}

// RFC 7636: a callback without the verifier bound to the authorization request
// must fail before the code is sent to the token endpoint.
func TestCallbackRejectsMissingPKCECookie(t *testing.T) {
	srv, _ := setupSessionAPI(t, auth.Identity{Email: "pkce@example.com"})
	h := srv.Handler()

	login := httptest.NewRecorder()
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	state := findCookie(login.Result().Cookies(), oauthStateCookie)
	tenantCk := findCookie(login.Result().Cookies(), oauthTenantCookie)
	nonceCk := findCookie(login.Result().Cookies(), oauthNonceCookie)

	cb := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+state.Value, nil)
	cb.AddCookie(state)
	cb.AddCookie(tenantCk)
	cb.AddCookie(nonceCk)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, cb)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "PKCE") {
		t.Fatalf("missing PKCE cookie must fail closed, got %d: %s", rec.Code, rec.Body)
	}
	if findCookie(rec.Result().Cookies(), auth.SessionCookie) != nil {
		t.Fatal("missing PKCE verifier must not mint a session")
	}
}

// A callback whose state does not match the cookie is rejected (CSRF defense).
func TestCallbackRejectsBadState(t *testing.T) {
	srv, _ := setupSessionAPI(t, auth.Identity{Email: "x@example.com"})
	h := srv.Handler()

	login := httptest.NewRecorder()
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	state := findCookie(login.Result().Cookies(), oauthStateCookie)
	tenantCk := findCookie(login.Result().Cookies(), oauthTenantCookie)

	cb := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=WRONG", nil)
	cb.AddCookie(state)
	cb.AddCookie(tenantCk)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, cb)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched state: want 400, got %d", rec.Code)
	}
}

func mustDecode(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body)
	}
}
