// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

type unitTenantIDPSource struct {
	items map[string]*store.TenantIDP
	err   error
}

func (s *unitTenantIDPSource) Get(_ context.Context, tenantID string) (*store.TenantIDP, error) {
	if s.err != nil {
		return nil, s.err
	}
	item, ok := s.items[tenantID]
	if !ok {
		return nil, store.ErrTenantIDPNotFound
	}
	cloned := *item
	cloned.Scopes = append([]string(nil), item.Scopes...)
	return &cloned, nil
}

type unitOIDCProvider struct{ issuer string }

func (p unitOIDCProvider) AuthCodeURL(string, string, string) string { return p.issuer }
func (unitOIDCProvider) Exchange(context.Context, string, string) (*auth.Identity, error) {
	return &auth.Identity{}, nil
}

type capturingOIDCFactory struct{ tenantIDs []string }

func (f *capturingOIDCFactory) For(_ context.Context, tenantID string) (auth.Provider, error) {
	f.tenantIDs = append(f.tenantIDs, tenantID)
	return unitOIDCProvider{issuer: "https://idp.example/authorize"}, nil
}

func errKind(t *testing.T, err error) apierror.Kind {
	t.Helper()
	de, ok := apierror.As(err)
	if !ok {
		t.Fatalf("not a domain error: %v", err)
	}
	return de.Kind
}

// requirePermission enforces authn (401) first, then the route permission (403),
// then runs the handler — the two-level boundary at the HTTP edge.
func TestRequirePermission(t *testing.T) {
	s := &Server{}
	ran := false
	h := apiHandler(func(http.ResponseWriter, *http.Request) error { ran = true; return nil })
	base := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)

	// No principal → 401, handler not run.
	if err := s.requirePermission(permTestRead, h)(httptest.NewRecorder(), base); errKind(t, err) != apierror.KindUnauthorized {
		t.Fatalf("missing principal: want 401, got %v", err)
	}
	if ran {
		t.Fatal("handler ran without authentication")
	}

	withPerm := base.WithContext(auth.WithPrincipal(base.Context(),
		&auth.Principal{TenantID: "t", Permissions: map[string]bool{permTestRead: true}}))

	// Principal lacks the required permission → 403.
	if err := s.requirePermission(permTestWrite, h)(httptest.NewRecorder(), withPerm); errKind(t, err) != apierror.KindForbidden {
		t.Fatalf("missing permission: want 403, got %v", err)
	}

	// Principal holds it → handler runs.
	ran = false
	if err := s.requirePermission(permTestRead, h)(httptest.NewRecorder(), withPerm); err != nil {
		t.Fatalf("allow: %v", err)
	}
	if !ran {
		t.Fatal("handler did not run when permitted")
	}

	// Empty permission requires only authentication.
	ran = false
	if err := s.requirePermission("", h)(httptest.NewRecorder(), withPerm); err != nil {
		t.Fatalf("authn-only: %v", err)
	}
	if !ran {
		t.Fatal("authn-only handler did not run")
	}
}

// SEC-005: when the server requires MFA, an authenticated single-factor
// session is refused (403) even with the permission; an MFA-satisfied session
// passes; and the default (off) never blocks a single-factor session.
func TestRequireMFA(t *testing.T) {
	h := apiHandler(func(http.ResponseWriter, *http.Request) error { return nil })
	base := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
	noMFA := base.WithContext(auth.WithPrincipal(base.Context(),
		&auth.Principal{TenantID: "t", Permissions: map[string]bool{permTestRead: true}}))
	withMFA := base.WithContext(auth.WithPrincipal(base.Context(),
		&auth.Principal{TenantID: "t", MFASatisfied: true, Permissions: map[string]bool{permTestRead: true}}))

	srv := &Server{requireMFA: true}
	if err := srv.requirePermission(permTestRead, h)(httptest.NewRecorder(), noMFA); errKind(t, err) != apierror.KindForbidden {
		t.Fatalf("single-factor under require-MFA: want 403, got %v", err)
	}
	if err := srv.requirePermission(permTestRead, h)(httptest.NewRecorder(), withMFA); err != nil {
		t.Fatalf("mfa-satisfied under require-MFA must pass: %v", err)
	}
	off := &Server{}
	if err := off.requirePermission(permTestRead, h)(httptest.NewRecorder(), noMFA); err != nil {
		t.Fatalf("require-MFA off must not block a single-factor session: %v", err)
	}
}

// Dev auth flows ONLY through the compiled-in hook (the test binary installs
// one in main_test.go; release binaries have none — RED-001). The hook
// synthesizes an all-permissions principal with an optional X-Probectl-Tenant
// override; a malformed override is rejected fail-closed with a 400.
func TestDevModeViaHook(t *testing.T) {
	s := &Server{cfg: &config.Config{AuthMode: "dev"}}

	captured := func(p **auth.Principal) http.Handler {
		return http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { *p = auth.PrincipalFrom(r.Context()) })
	}

	var p *auth.Principal
	s.authenticate(captured(&p)).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if p == nil || p.TenantID != tenancy.DefaultTenantID.String() {
		t.Fatalf("dev principal: %+v", p)
	}
	for _, k := range allPermissionKeys {
		if !p.Has(k) {
			t.Fatalf("dev principal missing %q", k)
		}
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Probectl-Tenant", "00000000-0000-0000-0000-0000000000ab")
	p = nil
	s.authenticate(captured(&p)).ServeHTTP(httptest.NewRecorder(), r)
	if p == nil || p.TenantID != "00000000-0000-0000-0000-0000000000ab" {
		t.Fatalf("tenant override: %+v", p)
	}

	// A malformed override is rejected (400), not silently defaulted.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("X-Probectl-Tenant", "not-a-uuid")
	rec := httptest.NewRecorder()
	p = nil
	s.authenticate(captured(&p)).ServeHTTP(rec, r2)
	if rec.Code != http.StatusBadRequest || p != nil {
		t.Fatalf("malformed override: code=%d principal=%+v (want 400, nil)", rec.Code, p)
	}
}

// RELEASE semantics (RED-001): with no hook compiled in, AuthMode=dev grants
// NOTHING — no principal is synthesized and the route layer 401s. main would
// have refused to boot already; this proves the defense-in-depth layer.
func TestDevModeAbsentGrantsNothing(t *testing.T) {
	old := devModeHook
	devModeHook = nil
	defer func() { devModeHook = old }()

	if DevModeAvailable() {
		t.Fatal("DevModeAvailable must be false with no hook")
	}
	s := &Server{cfg: &config.Config{AuthMode: "dev"}}
	var p *auth.Principal
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { p = auth.PrincipalFrom(r.Context()) })
	s.authenticate(h).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if p != nil {
		t.Fatalf("release build must synthesize NO principal in dev mode, got %+v", p)
	}
}

// Session mode with no authenticator (no DB) yields no principal — the route
// layer then returns 401.
func TestResolvePrincipalSessionNoAuthn(t *testing.T) {
	s := &Server{cfg: &config.Config{AuthMode: "session"}}
	if p := s.resolvePrincipal(httptest.NewRequest(http.MethodGet, "/", nil)); p != nil {
		t.Fatalf("want nil principal, got %+v", p)
	}
}

// In session mode without a session, a /v1 route is 401 at the HTTP edge.
func TestUnauthenticatedSessionModeIs401(t *testing.T) {
	cfg := &config.Config{HTTPAddr: ":0", AuthMode: "session", HSTSEnabled: true, HSTSMaxAge: time.Hour}
	s := New(cfg, logging.New(io.Discard, "error", "json"), nil, nil, nil, nil)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/tests", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

// U-001 boot test: with NO auth mode configured (an empty environment), the
// loaded default must be the secure "session" mode and the server must refuse
// unauthenticated /v1 requests — fail closed out of the box. Dev mode exists
// only as an explicit PROBECTL_AUTH_MODE=dev opt-in.
func TestBootNoAuthModeRefusesUnauthenticated(t *testing.T) {
	cfg, err := config.Load(func(string) string { return "" })
	if err != nil {
		t.Fatalf("load default config: %v", err)
	}
	if cfg.AuthMode != "session" {
		t.Fatalf("default auth mode = %q, want \"session\" (fail-closed)", cfg.AuthMode)
	}

	s := New(cfg, logging.New(io.Discard, "error", "json"), nil, nil, nil, nil)
	for _, path := range []string{"/v1/tests", "/v1/me"} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated GET %s with default config: want 401, got %d", path, rec.Code)
		}
	}

	// The dev principal must not exist unless dev mode was explicitly chosen.
	if p := s.resolvePrincipal(httptest.NewRequest(http.MethodGet, "/v1/tests", nil)); p != nil {
		t.Fatalf("default config synthesized a principal: %+v", p)
	}
}

// /v1/me returns the caller's tenant + effective permissions.
func TestMeEndpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	testServer(nil).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/me", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		TenantID       string   `json:"tenant_id"`
		TenantName     string   `json:"tenant_name"`
		TimeZone       string   `json:"time_zone"`
		Locale         string   `json:"locale"`
		TenantTimeZone string   `json:"tenant_time_zone"`
		TenantLocale   string   `json:"tenant_locale"`
		Permissions    []string `json:"permissions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.TenantID != tenancy.DefaultTenantID.String() {
		t.Fatalf("tenant_id = %s", body.TenantID)
	}
	if body.TenantName != tenancy.DefaultTenantID.String() {
		t.Fatalf("DB-less tenant_name = %s, want safe tenant id fallback", body.TenantName)
	}
	if body.TimeZone != "UTC" || body.Locale != "en" || body.TenantTimeZone != "UTC" || body.TenantLocale != "en" {
		t.Fatalf("preferences = timezone:%q locale:%q tenant_timezone:%q tenant_locale:%q",
			body.TimeZone, body.Locale, body.TenantTimeZone, body.TenantLocale)
	}
	if len(body.Permissions) != len(allPermissionKeys) {
		t.Fatalf("want %d permissions, got %v", len(allPermissionKeys), body.Permissions)
	}
}

// SSO login requires a configured provider; with none, login is 503 (unavailable)
// rather than a panic or a leak.
func TestLoginWithoutProviderConfigured(t *testing.T) {
	rec := httptest.NewRecorder()
	testServer(nil).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d: %s", rec.Code, rec.Body)
	}
}

func TestTenantIdPLoginUsesTenantHintAndIgnoresHost(t *testing.T) {
	srv := testServer(nil)
	factory := &capturingOIDCFactory{}
	srv.SetSSOProviderFactory(factory)

	hintedTenant := "22222222-2222-2222-2222-222222222222"
	hinted := httptest.NewRequest(http.MethodGet, "/auth/login?tenant="+hintedTenant, nil)
	hintedRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hintedRec, hinted)
	if hintedRec.Code != http.StatusFound || len(factory.tenantIDs) != 1 || factory.tenantIDs[0] != hintedTenant {
		t.Fatalf("tenant-hinted login: status=%d resolved=%v", hintedRec.Code, factory.tenantIDs)
	}

	factory.tenantIDs = nil
	hosted := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	hosted.Host = "status.acme.example:443"
	hostedRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hostedRec, hosted)
	if hostedRec.Code != http.StatusFound || len(factory.tenantIDs) != 1 || factory.tenantIDs[0] != tenancy.DefaultTenantID.String() {
		t.Fatalf("host-neutral login: status=%d resolved=%v", hostedRec.Code, factory.tenantIDs)
	}
}

func TestTenantIdPPerTenantResolutionAndEnvironmentFallback(t *testing.T) {
	env := &config.Config{
		OIDCIssuer: "https://env-idp.example", OIDCClientID: "env-client",
		OIDCClientSecret: "env-secret", OIDCRedirectURL: "https://probectl.example/auth/callback",
	}
	source := &unitTenantIDPSource{items: map[string]*store.TenantIDP{
		"tenant-a": {
			Issuer: "https://tenant-a-idp.example", ClientID: "tenant-a-client",
			ClientSecret: "tenant-a-secret", RedirectURL: "https://a.example/auth/callback",
			Scopes: []string{"openid", "email"}, Enabled: true,
		},
		"tenant-disabled": {Enabled: false},
	}}
	var built []auth.OIDCConfig
	factory := newOIDCFactory(env, nil)
	factory.idps = source
	factory.build = func(_ context.Context, cfg auth.OIDCConfig) (auth.Provider, error) {
		built = append(built, cfg)
		return unitOIDCProvider{issuer: cfg.Issuer}, nil
	}

	providerA, err := factory.For(context.Background(), "tenant-a")
	if err != nil || providerA.AuthCodeURL("", "", "") != "https://tenant-a-idp.example" {
		t.Fatalf("tenant A provider = %v, err=%v", providerA, err)
	}
	providerB, err := factory.For(context.Background(), "tenant-b")
	if err != nil || providerB.AuthCodeURL("", "", "") != env.OIDCIssuer {
		t.Fatalf("tenant B environment fallback = %v, err=%v", providerB, err)
	}
	disabled, err := factory.For(context.Background(), "tenant-disabled")
	if err != nil || disabled.AuthCodeURL("", "", "") != env.OIDCIssuer {
		t.Fatalf("disabled override environment fallback = %v, err=%v", disabled, err)
	}
	if len(built) != 3 {
		t.Fatalf("provider builds = %d, want one isolated config per requested tenant", len(built))
	}
	if built[0].ClientSecret != "tenant-a-secret" || built[1].ClientSecret != "env-secret" {
		t.Fatalf("tenant configuration crossed boundaries: %+v", built)
	}

	// Same configuration is cached, but changing this tenant's configuration
	// changes its secret-bearing fingerprint and forces a rebuild.
	if _, err := factory.For(context.Background(), "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if len(built) != 3 {
		t.Fatalf("unchanged tenant provider was rebuilt: %d", len(built))
	}
	source.items["tenant-a"].Issuer = "https://tenant-a-new.example"
	if _, err := factory.For(context.Background(), "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if len(built) != 4 || built[3].Issuer != "https://tenant-a-new.example" {
		t.Fatalf("updated tenant provider was not rebuilt: %+v", built)
	}
}

func TestTenantIdPMisconfigurationFailsClosedWithoutEnvironmentFallback(t *testing.T) {
	env := &config.Config{
		OIDCIssuer: "https://env-idp.example", OIDCClientID: "env-client",
		OIDCClientSecret: "env-secret", OIDCRedirectURL: "https://probectl.example/auth/callback",
	}
	source := &unitTenantIDPSource{items: map[string]*store.TenantIDP{
		"tenant-a": {
			Issuer: "http://unverified-idp.example", ClientID: "broken",
			ClientSecret: "broken-secret", RedirectURL: "https://a.example/auth/callback",
			Scopes: []string{"openid"}, Enabled: true,
		},
	}}
	factory := newOIDCFactory(env, nil)
	factory.idps = source
	builds := 0
	factory.build = func(context.Context, auth.OIDCConfig) (auth.Provider, error) {
		builds++
		return unitOIDCProvider{}, nil
	}
	if _, err := factory.For(context.Background(), "tenant-a"); err == nil {
		t.Fatal("present malformed tenant IdP must fail closed")
	}
	if builds != 0 {
		t.Fatal("malformed tenant IdP silently fell back to the environment provider")
	}

	source.items = map[string]*store.TenantIDP{}
	source.err = errors.New("decrypt failed")
	if _, err := factory.For(context.Background(), "tenant-a"); err == nil {
		t.Fatal("unreadable tenant IdP secret must fail closed")
	}
	if builds != 0 {
		t.Fatal("unreadable tenant IdP silently fell back to the environment provider")
	}
}
