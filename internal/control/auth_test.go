package control

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/apierror"
	"github.com/imfeelingtheagi/netctl/internal/auth"
	"github.com/imfeelingtheagi/netctl/internal/config"
	"github.com/imfeelingtheagi/netctl/internal/logging"
	"github.com/imfeelingtheagi/netctl/internal/tenancy"
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

// Dev auth mode synthesizes an all-permissions principal, with an optional
// X-Netctl-Tenant override — it keeps local dev and the /v1 test suite running
// without a real IdP.
func TestResolvePrincipalDevMode(t *testing.T) {
	s := &Server{cfg: &config.Config{AuthMode: "dev"}}

	p := s.resolvePrincipal(httptest.NewRequest(http.MethodGet, "/", nil))
	if p == nil || p.TenantID != tenancy.DefaultTenantID.String() {
		t.Fatalf("dev principal: %+v", p)
	}
	for _, k := range allPermissionKeys {
		if !p.Has(k) {
			t.Fatalf("dev principal missing %q", k)
		}
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Netctl-Tenant", "00000000-0000-0000-0000-0000000000ab")
	if got := s.resolvePrincipal(r).TenantID; got != "00000000-0000-0000-0000-0000000000ab" {
		t.Fatalf("tenant override: %s", got)
	}

	// A non-UUID override is ignored (falls back to the default tenant).
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("X-Netctl-Tenant", "not-a-uuid")
	if got := s.resolvePrincipal(r2).TenantID; got != tenancy.DefaultTenantID.String() {
		t.Fatalf("bad override should fall back to default, got %s", got)
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
