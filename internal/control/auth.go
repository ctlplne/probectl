// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
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
	permIRInvestigate      = "ir.investigate"
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
	permIRInvestigate,
	permAIQuery,
	ai.PermMetricsRead, ai.PermEventsRead, ai.PermEntitiesRead, ai.PermTopologyRead,
}

// OAuth transient cookies: a short-lived state (CSRF) + the tenant being logged
// into, so the callback can pick the right per-tenant provider.
const (
	oauthStateCookie  = "probectl_oauth_state"
	oauthNonceCookie  = "probectl_oauth_nonce"
	oauthPKCECookie   = "probectl_oauth_pkce"
	oauthTenantCookie = "probectl_oauth_tenant"
	oauthCookieTTL    = 10 * time.Minute
)

// permLoader implements auth.PermissionLoader over the RBAC store. It enforces
// the tenant boundary (RLS) when computing a user's effective permissions.
type permLoader struct{ pool *pgxpool.Pool }

func (l permLoader) ForUser(ctx context.Context, tenantID, userID string) ([]auth.PermissionGrant, error) {
	var grants []auth.PermissionGrant
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), l.pool, func(ctx context.Context, sc tenancy.Scope) error {
		g, err := store.Permissions{}.ForSubject(ctx, sc, "user", userID)
		grants = g
		return err
	})
	return grants, err
}

type tenantIDPSource interface {
	Get(context.Context, string) (*store.TenantIDP, error)
}

type cachedOIDCProvider struct {
	version  string
	provider auth.Provider
}

// oidcFactory resolves a tenant-scoped database override first and falls back
// to the deployment environment IdP only when the override is absent or
// explicitly disabled. A malformed/unreadable PRESENT override fails closed:
// it never silently authenticates the tenant against a different IdP.
type oidcFactory struct {
	cfg   *config.Config
	idps  tenantIDPSource
	build func(context.Context, auth.OIDCConfig) (auth.Provider, error)
	mu    sync.Mutex
	cache map[string]cachedOIDCProvider
}

func newOIDCFactory(cfg *config.Config, pool *pgxpool.Pool) *oidcFactory {
	f := &oidcFactory{cfg: cfg, build: auth.NewOIDCProvider, cache: map[string]cachedOIDCProvider{}}
	if pool != nil {
		f.idps = store.NewTenantIDPs(pool)
	}
	return f
}

func (f *oidcFactory) For(ctx context.Context, tenantID string) (auth.Provider, error) {
	cfg, source, err := f.resolveConfig(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	version := oidcConfigFingerprint(source, cfg)
	f.mu.Lock()
	if cached, ok := f.cache[tenantID]; ok && cached.version == version {
		f.mu.Unlock()
		return cached.provider, nil
	}
	f.mu.Unlock()

	// Discovery performs verified outbound HTTPS and can be slow. Do not hold
	// the cache mutex across it; a concurrent duplicate build is harmless.
	p, err := f.build(ctx, cfg)
	if err != nil {
		return nil, apierror.Unavailable("tenant SSO provider is unavailable").Wrap(err)
	}
	f.mu.Lock()
	if cached, ok := f.cache[tenantID]; ok && cached.version == version {
		f.mu.Unlock()
		return cached.provider, nil
	}
	f.cache[tenantID] = cachedOIDCProvider{version: version, provider: p}
	f.mu.Unlock()
	return p, nil
}

func (f *oidcFactory) resolveConfig(ctx context.Context, tenantID string) (auth.OIDCConfig, string, error) {
	if f.idps != nil {
		settings, err := f.idps.Get(ctx, tenantID)
		switch {
		case err == nil && settings.Enabled:
			cfg := auth.OIDCConfig{
				Issuer: settings.Issuer, ClientID: settings.ClientID,
				ClientSecret: settings.ClientSecret, RedirectURL: settings.RedirectURL,
				Scopes: append([]string(nil), settings.Scopes...),
			}
			if err := validateOIDCConfig(cfg); err != nil {
				return auth.OIDCConfig{}, "", apierror.Unavailable("tenant SSO configuration is invalid").Wrap(err)
			}
			return cfg, "tenant", nil
		case err == nil: // an explicitly disabled override deliberately uses env fallback
		case errors.Is(err, store.ErrTenantIDPNotFound):
		default:
			return auth.OIDCConfig{}, "", apierror.Unavailable("tenant SSO configuration is unavailable").Wrap(err)
		}
	}

	cfg := auth.OIDCConfig{
		Issuer:       f.cfg.OIDCIssuer,
		ClientID:     f.cfg.OIDCClientID,
		ClientSecret: f.cfg.OIDCClientSecret,
		RedirectURL:  f.cfg.OIDCRedirectURL,
	}
	if cfg.Issuer == "" && cfg.ClientID == "" && cfg.ClientSecret == "" && cfg.RedirectURL == "" {
		return auth.OIDCConfig{}, "", apierror.Unavailable("SSO is not configured")
	}
	if err := validateOIDCConfig(cfg); err != nil {
		return auth.OIDCConfig{}, "", apierror.Unavailable("deployment SSO configuration is invalid").Wrap(err)
	}
	return cfg, "environment", nil
}

func oidcConfigFingerprint(source string, cfg auth.OIDCConfig) string {
	material := strings.Join([]string{source, cfg.Issuer, cfg.ClientID, cfg.ClientSecret,
		cfg.RedirectURL, strings.Join(cfg.Scopes, "\x00")}, "\x01")
	return hex.EncodeToString(crypto.Hash([]byte(material)))
}

func validateOIDCConfig(cfg auth.OIDCConfig) error {
	if strings.TrimSpace(cfg.ClientID) == "" {
		return errors.New("OIDC client_id is required")
	}
	if strings.TrimSpace(cfg.ClientSecret) == "" {
		return errors.New("OIDC client_secret is required")
	}
	if err := validateOIDCHTTPSURL("issuer", cfg.Issuer); err != nil {
		return err
	}
	if err := validateOIDCHTTPSURL("redirect_url", cfg.RedirectURL); err != nil {
		return err
	}
	if len(cfg.Scopes) > 16 {
		return errors.New("OIDC scopes cannot contain more than 16 values")
	}
	seen := map[string]bool{}
	for _, scope := range cfg.Scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return errors.New("OIDC scopes cannot contain an empty value")
		}
		seen[scope] = true
	}
	if len(cfg.Scopes) > 0 && !seen["openid"] {
		return errors.New("OIDC scopes must include openid")
	}
	return nil
}

func validateOIDCHTTPSURL(name, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("OIDC %s must be an absolute HTTPS URL without credentials or fragment", name)
	}
	return nil
}

// setSSOProviderFactory overrides the SSO provider factory so tests can drive
// login with a mock IdP without real OIDC discovery.
func (s *Server) setSSOProviderFactory(f auth.ProviderFactory) { s.providers = f }

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

// authenticate is the middleware that resolves a request's principal (if any) and
// injects it into the context. Per-route enforcement (401/403) happens later.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Login/callback/logout establish or consume credentials themselves and
		// never read a Principal. Skipping ambient resolution here also prevents
		// a permission-change rotation in middleware from racing the callback's
		// required login rotation and leaving two successor sessions.
		if strings.HasPrefix(r.URL.Path, "/auth/") {
			next.ServeHTTP(w, r)
			return
		}
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
		if p := s.resolvePrincipalAndRotate(w, r); p != nil {
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
	return s.resolvePrincipalSession(nil, r)
}

// resolvePrincipalAndRotate is the HTTP-edge session path. It can return the
// replacement cookie required when effective authorization changed; callers
// without a ResponseWriter use resolvePrincipal and deliberately cannot rotate.
func (s *Server) resolvePrincipalAndRotate(w http.ResponseWriter, r *http.Request) *auth.Principal {
	return s.resolvePrincipalSession(w, r)
}

func (s *Server) resolvePrincipalSession(w http.ResponseWriter, r *http.Request) *auth.Principal {
	return s.resolvePrincipalSessionWith(w, r, s.resolveBearerPrincipal, s.loadSubjectAttributes)
}

// resolvePrincipalSessionWith keeps the bearer and subject-attribute lookups
// injectable for the bounded HTTP-edge regression test. Shipping callers always
// enter through resolvePrincipalSession, which supplies the real tenant-scoped
// token and user lookups.
func (s *Server) resolvePrincipalSessionWith(
	w http.ResponseWriter,
	r *http.Request,
	resolveBearer func(*http.Request, string) (*auth.Principal, error),
	loadAttributes func(context.Context, *auth.Principal) error,
) *auth.Principal {
	if token, ok := bearerTokenFromRequest(r); ok {
		p, err := resolveBearer(r, token)
		if err != nil {
			s.log.Warn("bearer token resolve failed", "error", err)
			return nil
		}
		return s.principalWithSubjectAttributes(r.Context(), p, loadAttributes)
	}
	if s.authn == nil {
		return nil
	}
	var (
		p           *auth.Principal
		replacement string
		err         error
	)
	if w == nil {
		p, err = s.authn.Resolve(r)
	} else {
		p, replacement, err = s.authn.ResolveAndRotate(r)
	}
	if err != nil {
		s.log.Warn("session resolve failed", "error", err)
		return nil
	}
	if replacement != "" {
		s.sessions.SetCookie(w, replacement)
	}
	return s.principalWithSubjectAttributes(r.Context(), p, loadAttributes)
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
	grants, err := permLoader{pool: s.pool}.ForUser(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	p := auth.PrincipalWithPermissionGrants(
		&auth.Principal{TenantID: tenantID, UserID: userID},
		grants,
	)
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

// principalWithSubjectAttributes attaches the complete subject attribute set or
// refuses the incomplete principal. Returning nil makes both bearer and session
// authentication fail closed before route RBAC can run.
func (s *Server) principalWithSubjectAttributes(
	ctx context.Context,
	p *auth.Principal,
	loadAttributes func(context.Context, *auth.Principal) error,
) *auth.Principal {
	if p == nil {
		return nil
	}
	if err := loadAttributes(ctx, p); err != nil {
		s.log.Warn("subject attribute load failed; authentication refused",
			"tenant_id", p.TenantID, "user_id", p.UserID, "error", err)
		return nil
	}
	return p
}

// loadSubjectAttributes attaches the principal's ABAC subject attributes (S31):
// the user's SCIM-provisioned attributes plus the derived "mfa" flag. They are
// read tenant-scoped (RLS), so a request can only carry its own tenant's data.
func (s *Server) loadSubjectAttributes(ctx context.Context, p *auth.Principal) error {
	if p == nil || s.pool == nil {
		return nil
	}
	return loadSubjectAttributesWith(ctx, p, s.inTenantID, (store.Users{}).Get)
}

func loadSubjectAttributesWith(
	ctx context.Context,
	p *auth.Principal,
	inTenant func(context.Context, string, func(context.Context, tenancy.Scope) error) error,
	getUser func(context.Context, tenancy.Scope, string) (*store.User, error),
) error {
	var directoryAttributes map[string]string
	if err := inTenant(ctx, p.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		u, err := getUser(ctx, sc, p.UserID)
		if err != nil {
			return err
		}
		directoryAttributes = u.Attributes
		return nil
	}); err != nil {
		return err
	}
	p.Attributes = composeSubjectAttributes(directoryAttributes, p.MFASatisfied)
	return nil
}

// composeSubjectAttributes combines mutable directory attributes with
// authentication-derived state. Reserved derived values are assigned last so
// SCIM input can neither forge nor downgrade the server's MFA decision.
func composeSubjectAttributes(directory map[string]string, mfaSatisfied bool) map[string]string {
	attrs := make(map[string]string, len(directory)+1)
	for k, v := range directory {
		attrs[k] = v
	}
	attrs["mfa"] = boolStr(mfaSatisfied)
	return attrs
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
	return s.requirePermissionMode(perm, false, h)
}

// requireAnyPermission is the route-edge half of resource-scoped RBAC. It lets
// a valid scoped grant reach a handler that will first resolve the concrete
// resource through tenant RLS and then call Principal.HasAt on that lineage.
func (s *Server) requireAnyPermission(perm string, h apiHandler) apiHandler {
	return s.requirePermissionMode(perm, true, h)
}

func (s *Server) requirePermissionMode(perm string, allowScoped bool, h apiHandler) apiHandler {
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
			// One door for the whole order (S-6357f747): RBAC per mode, then
			// the tenant's ABAC deny-override — a policy may DENY a permission
			// an RBAC role grants (S31) — with policy loading fail closed.
			mode := auth.RBACGlobal
			if allowScoped {
				mode = auth.RBACAnyScope
			}
			if err := s.authorize(r.Context(), p, perm, mode, nil); err != nil {
				return err
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
	codeVerifier, err := crypto.NewPKCEVerifier()
	if err != nil {
		return err
	}
	s.setOAuthCookie(w, oauthStateCookie, state)
	s.setOAuthCookie(w, oauthNonceCookie, nonce)
	s.setOAuthCookie(w, oauthPKCECookie, codeVerifier)
	s.setOAuthCookie(w, oauthTenantCookie, tid.String())
	http.Redirect(w, r, prov.AuthCodeURL(state, nonce, codeVerifier), http.StatusFound)
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
	pkceCookie, _ := r.Cookie(oauthPKCECookie)
	if pkceCookie == nil || pkceCookie.Value == "" {
		return apierror.Unauthorized("missing PKCE code verifier")
	}
	// The verifier is a single-login credential. Expire it before the network
	// exchange so callback retries cannot reuse it after any exchange attempt.
	s.clearOAuthCookie(w, oauthPKCECookie)
	ident, err := prov.Exchange(r.Context(), code, pkceCookie.Value)
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

	grants, err := (permLoader{pool: s.pool}).ForUser(r.Context(), tid.String(), user.ID)
	if err != nil {
		return err
	}
	newSession := auth.Session{
		TenantID:          tid.String(),
		UserID:            user.ID,
		Email:             user.Email,
		DisplayName:       user.DisplayName,
		MFASatisfied:      ident.MFASatisfied, // SEC-005: from the ID token's amr/acr
		TimeZone:          prefOrDefault(ident.TimeZone, "UTC"),
		Locale:            prefOrDefault(ident.Locale, "en"),
		TenantTimeZone:    "UTC",
		TenantLocale:      "en",
		AuthorizationHash: auth.PermissionGrantFingerprint(grants),
	}
	// A completed IdP login is fresh authentication authority, not a permission
	// refresh. It atomically consumes any predecessor while adopting the new
	// identity/MFA/lifetime; a concurrent loser must not mint a second session.
	token, err := s.sessions.ReplaceAuthenticated(r.Context(), auth.TokenFromRequest(r), newSession)
	if errors.Is(err, auth.ErrSessionNotFound) {
		return apierror.Unauthorized("session was already replaced by a concurrent login")
	}
	if err != nil {
		return err
	}
	// Successful login ends both backoff chains (U-024).
	s.authLimiter.Success("ip:" + s.clientIP(r))
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
	tenantName, tenantSlug := p.TenantID, p.TenantID
	if s.pool != nil {
		if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			// The principal's tenant is both the explicit predicate and the FORCE
			// RLS setting. /me must never become a tenant-name enumeration path.
			return sc.Q.QueryRow(ctx, `
				SELECT name, slug
				  FROM public.probectl_current_tenant_identity()
				 WHERE id = $1`, sc.Tenant.String()).Scan(&tenantName, &tenantSlug)
		}); err != nil {
			return err
		}
	}
	perms := make([]string, 0, len(p.Permissions))
	for k := range p.Permissions {
		perms = append(perms, k)
	}
	sort.Strings(perms)
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id":        p.TenantID,
		"tenant_name":      tenantName,
		"tenant_slug":      tenantSlug,
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
