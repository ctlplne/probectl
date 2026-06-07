package control

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

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
		TenantID    string   `json:"tenant_id"`
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.TenantID != tenancy.DefaultTenantID.String() {
		t.Fatalf("tenant_id = %s", body.TenantID)
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
