//go:build integration

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/config"
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
type fakeProvider struct{ ident auth.Identity }

func (f fakeProvider) AuthCodeURL(state, _ string) string {
	return "https://idp.example/authorize?state=" + state
}

func (f fakeProvider) Exchange(context.Context, string) (*auth.Identity, error) {
	id := f.ident
	return &id, nil
}

type fakeFactory struct{ p auth.Provider }

func (f fakeFactory) For(context.Context, string) (auth.Provider, error) { return f.p, nil }

func setupSessionAPI(t *testing.T, ident auth.Identity) (*Server, *store.DB) {
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
	srv.SetSSOProviderFactory(fakeFactory{p: fakeProvider{ident: ident}})
	return srv, db
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
	}
	srv, db := setupSessionAPI(t, ident)
	h := srv.Handler()

	// 1. Begin login → 302 + transient state/tenant cookies.
	login := httptest.NewRecorder()
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if login.Code != http.StatusFound {
		t.Fatalf("login: want 302, got %d: %s", login.Code, login.Body)
	}
	state := findCookie(login.Result().Cookies(), oauthStateCookie)
	tenantCk := findCookie(login.Result().Cookies(), oauthTenantCookie)
	if state == nil || state.Value == "" {
		t.Fatal("login did not set the oauth state cookie")
	}

	// 2. Callback with matching state → 302 + session cookie.
	cb := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+state.Value, nil)
	cb.AddCookie(state)
	cb.AddCookie(tenantCk)
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

	// 3. /v1/me with the session → 200; the JIT-provisioned user has no roles.
	me := withCookie(t, h, http.MethodGet, "/v1/me", sess)
	if me.Code != http.StatusOK {
		t.Fatalf("me: want 200, got %d: %s", me.Code, me.Body)
	}
	var meBody struct {
		UserID      string   `json:"user_id"`
		Email       string   `json:"email"`
		Permissions []string `json:"permissions"`
	}
	mustDecode(t, me, &meBody)
	if meBody.Email != ident.Email {
		t.Fatalf("me email = %s", meBody.Email)
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
	// before the handler, so the missing body never matters.
	bindRole(t, db, meBody.UserID, "viewer")
	if rec := withCookie(t, h, http.MethodGet, "/v1/tests", sess); rec.Code != http.StatusOK {
		t.Fatalf("viewer read: want 200, got %d: %s", rec.Code, rec.Body)
	}
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
