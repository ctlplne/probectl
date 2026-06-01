package control

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/netctl/internal/apierror"
	"github.com/imfeelingtheagi/netctl/internal/auth"
	"github.com/imfeelingtheagi/netctl/internal/config"
	"github.com/imfeelingtheagi/netctl/internal/store"
	"github.com/imfeelingtheagi/netctl/internal/tenancy"
)

// RBAC permission keys (mirror migrations 0003 + 0013). Routes declare the key a
// caller must hold; the seeded admin/editor/viewer roles grant them.
const (
	permTestRead      = "test.read"
	permTestWrite     = "test.write"
	permAgentRead     = "agent.read"
	permAgentWrite    = "agent.write"
	permAlertRead     = "alert.read"
	permAlertWrite    = "alert.write"
	permIncidentRead  = "incident.read"
	permIncidentWrite = "incident.write"
)

// allPermissionKeys is the full catalog — granted to the dev-mode principal so
// local/dev (and the existing /v1 integration tests) run without a real IdP.
var allPermissionKeys = []string{
	permTestRead, permTestWrite,
	permAgentRead, permAgentWrite,
	permAlertRead, permAlertWrite,
	permIncidentRead, permIncidentWrite,
}

// OAuth transient cookies: a short-lived state (CSRF) + the tenant being logged
// into, so the callback can pick the right per-tenant provider.
const (
	oauthStateCookie  = "netctl_oauth_state"
	oauthTenantCookie = "netctl_oauth_tenant"
	oauthCookieTTL    = 10 * time.Minute
)

// permLoader implements auth.PermissionLoader over the RBAC store. It enforces
// the tenant boundary (RLS) when computing a user's effective permissions.
type permLoader struct{ pool *pgxpool.Pool }

func (l permLoader) ForUser(ctx context.Context, tenantID, userID string) ([]string, error) {
	var keys []string
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), l.pool, func(ctx context.Context, sc tenancy.Scope) error {
		k, err := store.Permissions{}.ForSubject(ctx, sc, "user", userID)
		keys = k
		return err
	})
	return keys, err
}

// oidcFactory is the default ProviderFactory: a single env-configured OIDC IdP,
// shared across tenants until DB-backed per-tenant IdP config lands (the For()
// seam keeps that future change local). Providers are built lazily — OIDC
// discovery hits the network — and cached. build is injectable so tests can
// supply a provider without real discovery.
type oidcFactory struct {
	cfg   *config.Config
	build func(context.Context, auth.OIDCConfig) (auth.Provider, error)
	mu    sync.Mutex
	cache map[string]auth.Provider
}

func newOIDCFactory(cfg *config.Config) *oidcFactory {
	return &oidcFactory{cfg: cfg, build: auth.NewOIDCProvider, cache: map[string]auth.Provider{}}
}

func (f *oidcFactory) For(ctx context.Context, tenantID string) (auth.Provider, error) {
	if f.cfg.OIDCIssuer == "" {
		return nil, apierror.Unavailable("SSO is not configured")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.cache[tenantID]; ok {
		return p, nil
	}
	p, err := f.build(ctx, auth.OIDCConfig{
		Issuer:       f.cfg.OIDCIssuer,
		ClientID:     f.cfg.OIDCClientID,
		ClientSecret: f.cfg.OIDCClientSecret,
		RedirectURL:  f.cfg.OIDCRedirectURL,
	})
	if err != nil {
		return nil, err
	}
	f.cache[tenantID] = p
	return p, nil
}

// SetSSOProviderFactory overrides the SSO provider factory. It is the seam for
// future DB-backed per-tenant IdP configuration, and lets tests drive login with
// a mock IdP without real OIDC discovery.
func (s *Server) SetSSOProviderFactory(f auth.ProviderFactory) { s.providers = f }

// authenticate is the middleware that resolves a request's principal (if any) and
// injects it into the context. It never rejects — per-route enforcement decides.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := s.resolvePrincipal(r); p != nil {
			r = r.WithContext(auth.WithPrincipal(r.Context(), p))
		}
		next.ServeHTTP(w, r)
	})
}

// resolvePrincipal returns the caller's principal, or nil when unauthenticated.
// In "dev" mode it synthesizes an all-permissions principal (tenant from the
// X-Netctl-Tenant override or the default) — never used in production. In
// "session" mode it resolves the session cookie to a real principal.
func (s *Server) resolvePrincipal(r *http.Request) *auth.Principal {
	if s.cfg.AuthMode == "dev" {
		tid := tenancy.DefaultTenantID
		if h := r.Header.Get("X-Netctl-Tenant"); h != "" && uuidRe.MatchString(h) {
			tid = tenancy.ID(h)
		}
		perms := make(map[string]bool, len(allPermissionKeys))
		for _, k := range allPermissionKeys {
			perms[k] = true
		}
		return &auth.Principal{TenantID: tid.String(), UserID: "dev", Email: "dev@netctl.local", DisplayName: "Dev", Permissions: perms}
	}
	if s.authn == nil {
		return nil
	}
	p, err := s.authn.Resolve(r)
	if err != nil {
		s.log.Warn("session resolve failed", "error", err)
		return nil
	}
	return p
}

// principalTenant returns the caller's tenant ID, or a 401 when unauthenticated.
// Used by handlers that key a non-RLS store (e.g. the path store) by tenant; RLS
// handlers go through inTenant instead.
func (s *Server) principalTenant(r *http.Request) (string, error) {
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		return "", apierror.Unauthorized("authentication required")
	}
	return p.TenantID, nil
}

// requirePermission wraps an /v1 handler with authn + RBAC enforcement: 401 when
// unauthenticated, 403 when the principal lacks perm. perm "" requires only that
// the caller is authenticated. The tenant boundary is enforced first (the
// principal already carries exactly one tenant).
func (s *Server) requirePermission(perm string, h apiHandler) apiHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		p := auth.PrincipalFrom(r.Context())
		if p == nil {
			return apierror.Unauthorized("authentication required")
		}
		if perm != "" && !p.Has(perm) {
			return apierror.Forbidden("missing permission: " + perm)
		}
		return h(w, r)
	}
}

// --- SSO login handlers (public; not /v1) ---

// handleLogin begins the OIDC authorization-code flow: it resolves the target
// tenant, sets short-lived state+tenant cookies, and redirects to the IdP.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) error {
	tid := tenancy.DefaultTenantID
	if q := r.URL.Query().Get("tenant"); q != "" {
		if !uuidRe.MatchString(q) {
			return apierror.BadRequest("tenant must be a tenant UUID")
		}
		tid = tenancy.ID(q)
	}
	prov, err := s.providers.For(r.Context(), tid.String())
	if err != nil {
		return err
	}
	state, err := auth.RandomToken()
	if err != nil {
		return err
	}
	nonce, err := auth.RandomToken()
	if err != nil {
		return err
	}
	s.setOAuthCookie(w, oauthStateCookie, state)
	s.setOAuthCookie(w, oauthTenantCookie, tid.String())
	http.Redirect(w, r, prov.AuthCodeURL(state, nonce), http.StatusFound)
	return nil
}

// handleCallback completes login: it checks the CSRF state, exchanges the code,
// provisions/loads the user within the tenant, mints a session, and sets the
// session cookie.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		return apierror.Unauthorized("sso error: " + errCode)
	}
	stateCookie, _ := r.Cookie(oauthStateCookie)
	if stateCookie == nil || q.Get("state") == "" || stateCookie.Value != q.Get("state") {
		return apierror.BadRequest("invalid oauth state")
	}
	tid := tenancy.DefaultTenantID
	if c, _ := r.Cookie(oauthTenantCookie); c != nil && uuidRe.MatchString(c.Value) {
		tid = tenancy.ID(c.Value)
	}
	code := q.Get("code")
	if code == "" {
		return apierror.BadRequest("missing authorization code")
	}
	prov, err := s.providers.For(r.Context(), tid.String())
	if err != nil {
		return err
	}
	ident, err := prov.Exchange(r.Context(), code)
	if err != nil {
		s.log.Warn("sso exchange failed", "error", err)
		return apierror.Unauthorized("sso exchange failed")
	}
	if ident.Email == "" {
		return apierror.Unauthorized("identity provider returned no email")
	}

	var user *store.User
	err = tenancy.InTenant(tenancy.WithTenant(r.Context(), tid), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		u, e := store.Users{}.GetByEmail(ctx, sc, ident.Email)
		if e != nil {
			if de, ok := apierror.As(e); ok && de.Kind == apierror.KindNotFound {
				// Just-in-time provisioning: a first-time SSO user is created with
				// NO roles (secure default) — an admin grants access explicitly.
				u, e = store.Users{}.Create(ctx, sc, ident.Email, ident.DisplayName)
			}
		}
		user = u
		return e
	})
	if err != nil {
		return err
	}

	token, err := s.sessions.Issue(r.Context(), auth.Session{
		TenantID:    tid.String(),
		UserID:      user.ID,
		Email:       user.Email,
		DisplayName: user.DisplayName,
	})
	if err != nil {
		return err
	}
	s.clearOAuthCookie(w, oauthStateCookie)
	s.clearOAuthCookie(w, oauthTenantCookie)
	s.sessions.SetCookie(w, token)
	http.Redirect(w, r, "/", http.StatusFound)
	return nil
}

// handleLogout revokes the session and clears the cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) error {
	if s.sessions != nil {
		if err := s.sessions.Revoke(r.Context(), auth.TokenFromRequest(r)); err != nil {
			return err
		}
		s.sessions.ClearCookie(w)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// handleMe returns the authenticated caller's tenant, identity, and effective
// permissions. Requires authentication but no specific permission.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) error {
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		return apierror.Unauthorized("authentication required")
	}
	perms := make([]string, 0, len(p.Permissions))
	for k := range p.Permissions {
		perms = append(perms, k)
	}
	sort.Strings(perms)
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id":     p.TenantID,
		"user_id":       p.UserID,
		"email":         p.Email,
		"display_name":  p.DisplayName,
		"mfa_satisfied": p.MFASatisfied,
		"permissions":   perms,
	})
	return nil
}

// setOAuthCookie writes a short-lived, HttpOnly transient OAuth cookie.
func (s *Server) setOAuthCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLSEnabled(),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(oauthCookieTTL),
	})
}

func (s *Server) clearOAuthCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLSEnabled(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
