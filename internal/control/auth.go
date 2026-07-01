// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/branding"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// RBAC permission keys (mirror migrations 0003 + 0013). Routes declare the key a
// caller must hold; the seeded admin/editor/viewer roles grant them.
const (
	permTestRead           = "test.read"
	permTestWrite          = "test.write"
	permTestAllowPrivate   = "test.allow_private"
	permTestInsecureTLS    = "test.insecure_tls"
	permTenantRead         = "tenant.read"
	permAgentRead          = "agent.read"
	permAgentWrite         = "agent.write"
	permAlertRead          = "alert.read"
	permAlertWrite         = "alert.write"
	permIncidentRead       = "incident.read"
	permIncidentWrite      = "incident.write"
	permOrgRead            = "org.read"
	permOrgWrite           = "org.write"
	permChangeRead         = "change.read"
	permFlowRead           = "flow.read"
	permMetricsRead        = "metrics.read"
	permMetricsWrite       = "metrics.write"
	permCMDBRead           = "cmdb.read"
	permThreatRead         = "threat.read"
	permAuditRead          = "audit.read"
	permAIQuery            = "ai.query"
	permDirectoryRead      = "directory.read"
	permDirectoryWrite     = "directory.write"
	permLifecycleExp       = "lifecycle.export"
	permLifecycleErase     = "lifecycle.erase"
	permSecurityKeys       = "security.keys"
	permFairnessRead       = "fairness.read"
	permDiagnosticsRead    = "diagnostics.read"
	permRemediationPropose = "remediation.propose"
	permRemediationApprove = "remediation.approve"
)

// allPermissionKeys is the full catalog — granted to the dev-mode principal so
// local/dev (and the existing /v1 integration tests) run without a real IdP.
var allPermissionKeys = []string{
	permTestRead, permTestWrite, permTestAllowPrivate, permTestInsecureTLS,
	permTenantRead,
	permAgentRead, permAgentWrite,
	permAlertRead, permAlertWrite,
	permIncidentRead, permIncidentWrite,
	permOrgRead, permOrgWrite,
	permChangeRead,
	permFlowRead,
	permMetricsWrite, permCMDBRead, permThreatRead,
	permDirectoryRead, permDirectoryWrite,
	permLifecycleExp, permLifecycleErase,
	permSecurityKeys,
	permFairnessRead,
	permDiagnosticsRead,
	permRemediationPropose, permRemediationApprove,
	permAuditRead,
	permAIQuery,
	ai.PermMetricsRead, ai.PermEventsRead, ai.PermEntitiesRead, ai.PermTopologyRead,
}

// OAuth transient cookies: a short-lived state (CSRF) + the tenant being logged
// into, so the callback can pick the right per-tenant provider.
const (
	oauthStateCookie  = "probectl_oauth_state"
	oauthNonceCookie  = "probectl_oauth_nonce"
	oauthTenantCookie = "probectl_oauth_tenant"
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

// devModeHook is the ONLY entry point to dev-auth behavior. It is nil unless
// the binary was built with -tags devauth (internal/control/devauth.go), so a
// RELEASE binary contains no dev-auth logic, no dev literals, and nothing to
// misconfigure (RED-001/SEC-001 — the bypass is compiled out, not just
// warned about). The test binary installs its own hook (main_test.go); it
// never ships. The hook may fully handle the request (handled=true, e.g. a
// malformed tenant-override header → 400).
var devModeHook func(s *Server, w http.ResponseWriter, r *http.Request) (p *auth.Principal, handled bool)

// DevModeAvailable reports whether this binary is even capable of dev auth
// (i.e. was built with -tags devauth). main refuses AuthMode=dev otherwise.
func DevModeAvailable() bool { return devModeHook != nil }

// devModeActive flips on (once) when a server actually starts in dev mode —
// exported via DevModeActive for self-telemetry surfaces.
var devModeActive atomic.Bool

// DevModeActive reports whether any server in this process is serving the
// all-permissions dev principal.
func DevModeActive() bool { return devModeActive.Load() }

// authenticate is the middleware that resolves a request's principal (if any) and
// injects it into the context. Per-route enforcement (401/403) happens later.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dev auth exists only behind the compiled-in hook. In a release
		// build (hook nil) AuthMode=dev grants NOTHING — requests fall
		// through unauthenticated and the route layer 401s (and main has
		// already refused to boot; this is defense-in-depth).
		if s.cfg.AuthMode == "dev" && devModeHook != nil {
			p, handled := devModeHook(s, w, r)
			if handled {
				return
			}
			if p != nil {
				r = r.WithContext(auth.WithPrincipal(r.Context(), p))
			}
			next.ServeHTTP(w, r)
			return
		}
		if p := s.resolvePrincipal(r); p != nil {
			r = r.WithContext(auth.WithPrincipal(r.Context(), p))
		}
		next.ServeHTTP(w, r)
	})
}

// resolvePrincipal returns the caller's principal, or nil when unauthenticated,
// by resolving a bearer token or session cookie to a real principal. Dev auth
// never reaches here — it exists only behind devModeHook (compiled in via
// -tags devauth).
func (s *Server) resolvePrincipal(r *http.Request) *auth.Principal {
	if token, ok := bearerTokenFromRequest(r); ok {
		p, err := s.resolveBearerPrincipal(r, token)
		if err != nil {
			s.log.Warn("bearer token resolve failed", "error", err)
			return nil
		}
		s.loadSubjectAttributes(r.Context(), p)
		return p
	}
	if s.authn == nil {
		return nil
	}
	p, err := s.authn.Resolve(r)
	if err != nil {
		s.log.Warn("session resolve failed", "error", err)
		return nil
	}
	s.loadSubjectAttributes(r.Context(), p)
	return p
}

func bearerTokenFromRequest(r *http.Request) (string, bool) {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if h == "" {
		return "", false
	}
	scheme, token, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return "", true
	}
	return strings.TrimSpace(token), true
}

func (s *Server) resolveBearerPrincipal(r *http.Request, token string) (*auth.Principal, error) {
	if s.pool == nil {
		return nil, store.ErrInvalidToken
	}
	ctx := r.Context()
	tenantID, userID, err := store.NewMCPTokens(s.pool).Authenticate(ctx, crypto.Hash([]byte(token)))
	if err != nil {
		return nil, err
	}
	if asserted := strings.TrimSpace(r.Header.Get("X-Probectl-Tenant")); asserted != "" && asserted != tenantID {
		return nil, store.ErrInvalidToken
	}
	keys, err := permLoader{pool: s.pool}.ForUser(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	perms := make(map[string]bool, len(keys))
	for _, k := range keys {
		perms[k] = true
	}
	p := &auth.Principal{TenantID: tenantID, UserID: userID, Permissions: perms}
	_ = s.inTenantID(ctx, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		u, err := (store.Users{}).Get(ctx, sc, userID)
		if err != nil {
			return err
		}
		p.Email = u.Email
		p.DisplayName = u.DisplayName
		return nil
	})
	return p, nil
}

// loadSubjectAttributes attaches the principal's ABAC subject attributes (S31):
// the user's SCIM-provisioned attributes plus the derived "mfa" flag. They are
// read tenant-scoped (RLS), so a request can only carry its own tenant's data.
func (s *Server) loadSubjectAttributes(ctx context.Context, p *auth.Principal) {
	if p == nil || s.pool == nil {
		return
	}
	attrs := map[string]string{"mfa": boolStr(p.MFASatisfied)}
	if err := s.inTenantID(ctx, p.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		if u, err := (store.Users{}).Get(ctx, sc, p.UserID); err == nil {
			for k, v := range u.Attributes {
				attrs[k] = v
			}
		}
		return nil
	}); err != nil {
		// CODE-002: a scope-setup fault means we couldn't load subject ABAC
		// attributes — log it (a transient fault should not silently evaluate
		// ABAC against an empty attribute set).
		s.log.Warn("loadSubjectAttributes: tenant scope failed", "tenant_id", p.TenantID, "user_id", p.UserID, "error", err.Error())
	}
	p.Attributes = attrs
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
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
		// Tenant lifecycle (S-T1): a suspended/offboarded tenant's users are
		// rejected. Keyed strictly by the principal's OWN tenant — the check
		// can never consult another tenant's state.
		if err := s.checkTenantLifecycle(r, p.TenantID); err != nil {
			return err
		}
		// SEC-005: when the deployment requires MFA (PROBECTL_REQUIRE_MFA), a
		// session the IdP did not assert a second factor for is refused — at
		// REQUEST time, so even single-factor sessions minted before the flag
		// was set are rejected. Default off (no change for single-factor deploys).
		if s.requireMFA && !p.MFASatisfied {
			return apierror.Forbidden("multi-factor authentication required")
		}
		if perm != "" {
			if !p.Has(perm) {
				return apierror.Forbidden("missing permission: " + perm)
			}
			// ABAC over RBAC (S31): a tenant attribute policy may DENY a permission an
			// RBAC role grants (e.g. contractors can't write, step-up MFA required).
			if s.abacDenies(r.Context(), p, perm, nil) {
				return apierror.Forbidden("denied by an attribute policy: " + perm)
			}
		}
		return h(w, r)
	}
}

// --- SSO login handlers (public; not /v1) ---

// handleLogin begins the OIDC authorization-code flow: it resolves the target
// tenant, sets short-lived state+tenant cookies, and redirects to the IdP.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) error {
	tid := tenancy.DefaultTenantID
	// Custom-domain login (S-T4): a request arriving on a tenant's branded
	// domain logs into THAT tenant — no ?tenant= needed. An explicit
	// parameter still wins (operator tooling).
	if mapped := branding.TenantForHost(r.Context(), branding.NormalizeHost(r.Host)); mapped != "" {
		tid = tenancy.ID(mapped)
	}
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
	s.setOAuthCookie(w, oauthNonceCookie, nonce)
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
	// SEC-001: compare the single-use CSRF state in constant time (consistent
	// with the rest of the auth code) so a timing side channel can't probe the
	// expected value byte-by-byte.
	if stateCookie == nil || q.Get("state") == "" ||
		!crypto.ConstantTimeEqual([]byte(stateCookie.Value), []byte(q.Get("state"))) {
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
	// SEC-004: the ID token's nonce claim must equal the value minted at
	// login (stored in the transient cookie). A missing cookie or a mismatch
	// REFUSES the login — replayed/substituted ID tokens fail closed.
	nonceCookie, _ := r.Cookie(oauthNonceCookie)
	// SEC-001: constant-time compare of the single-use replay nonce.
	if nonceCookie == nil || nonceCookie.Value == "" ||
		!crypto.ConstantTimeEqual([]byte(ident.Nonce), []byte(nonceCookie.Value)) {
		s.log.Warn("sso nonce mismatch", "have_cookie", nonceCookie != nil)
		return apierror.Unauthorized("oidc nonce mismatch")
	}
	s.clearOAuthCookie(w, oauthNonceCookie)
	// Per-account throttle (U-024): a locked account is refused even with a
	// successful IdP exchange; later failures below count against it.
	if err := s.checkAccountThrottle(w, tid.String(), ident.Email); err != nil {
		return err
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
		if e != nil {
			return e
		}
		user = u
		// Record the authentication as a data-access action, in the same tx
		// (tamper-evident, RLS-scoped to the tenant the login resolved to).
		_, e = audit.TenantAppend(ctx, sc, ident.Email, "auth.login", u.ID, map[string]any{"subject": ident.Subject})
		return e
	})
	if err != nil {
		s.authLimiter.Fail(acctKey(tid.String(), ident.Email))
		return err
	}

	token, err := s.sessions.Issue(r.Context(), auth.Session{
		TenantID:       tid.String(),
		UserID:         user.ID,
		Email:          user.Email,
		DisplayName:    user.DisplayName,
		MFASatisfied:   ident.MFASatisfied, // SEC-005: from the ID token's amr/acr
		TimeZone:       prefOrDefault(ident.TimeZone, "UTC"),
		Locale:         prefOrDefault(ident.Locale, "en"),
		TenantTimeZone: "UTC",
		TenantLocale:   "en",
	})
	if err != nil {
		return err
	}
	// Successful login ends both backoff chains (U-024).
	s.authLimiter.Success("ip:" + clientIP(r))
	s.authLimiter.Success(acctKey(tid.String(), ident.Email))
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
		"tenant_id":        p.TenantID,
		"user_id":          p.UserID,
		"email":            p.Email,
		"display_name":     p.DisplayName,
		"mfa_satisfied":    p.MFASatisfied,
		"time_zone":        prefOrDefault(p.TimeZone, "UTC"),
		"locale":           prefOrDefault(p.Locale, "en"),
		"tenant_time_zone": prefOrDefault(p.TenantTimeZone, "UTC"),
		"tenant_locale":    prefOrDefault(p.TenantLocale, "en"),
		"permissions":      perms,
	})
	return nil
}

func prefOrDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// setOAuthCookie writes a short-lived, HttpOnly transient OAuth cookie.
func (s *Server) setOAuthCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure(),
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
		Secure:   s.cfg.CookieSecure(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
