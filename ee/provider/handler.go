// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// See ee/doc.go for the boundary rules every ee/ file observes.

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	coreaudit "github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/httpbody"
)

// The provider HTTP surface, mounted by core at /provider/ (an opaque
// http.Handler — core never imports this package; the licensed build attaches
// it at the main.go seam). Operator authn is the handler's own; tenant
// sessions and the dev principal mean nothing here, with ONE deliberate
// exception: the consent endpoints, which authenticate the TENANT session —
// consent belongs to the tenant, not to operators.

// TenantAuth resolves a tenant session plus the complete tenant authorization
// context needed by the consent leg. AuthorizationContext must return the
// session user's RBAC permissions, subject attributes, and policies loaded
// inside that tenant's storage scope; any incomplete load returns an error.
type TenantAuth interface {
	ResolveSession(ctx context.Context, token string) (*auth.Session, error)
	AuthorizationContext(ctx context.Context, session *auth.Session) (*auth.Principal, []auth.Policy, error)
}

// consentPermission is the tenant-side permission that authorizes deciding a
// break-glass request (tenant admins hold directory.write).
const consentPermission = "directory.write"

// Handler serves /provider/v1/*.
type Handler struct {
	svc        *Service
	sessions   *Sessions
	tenantAuth TenantAuth
	log        *slog.Logger

	// limiter throttles the operator login (SEC-003): per source IP and per
	// account, exponential lockout, lockouts audited to the PROVIDER stream.
	// The tenant login has had this since U-024; the provider plane is the
	// HIGHEST-privilege login, so it gets the same brake.
	limiter *auth.Limiter

	bootstrapToken string
	secureCookies  bool

	// metering (S-T3): nil unless the metering feature is licensed — then
	// the usage/quota routes answer not_found (hidden-unlicensed).
	metering *Metering

	// lifecycle (S-T5): the CORE erase engine (the provider view of it).
	lifecycle Lifecycle

	// fairness (S-T7): operator views over the CORE gate + policy store.
	fairness *Fairness

	// governance (S-EE3): the data-governance policy + composed view.
	governance *Governance

	mux *http.ServeMux
}

// RouteDecl is one provider route (kept as a table so the provider OpenAPI
// self-test can assert spec completeness, mirroring the core gate).
type RouteDecl struct {
	Method  string
	Pattern string
}

// routes is the provider plane's route table.
func routes() []RouteDecl {
	base := []RouteDecl{
		{http.MethodPost, "/provider/v1/auth/bootstrap"},
		{http.MethodPost, "/provider/v1/auth/enroll/start"},
		{http.MethodPost, "/provider/v1/auth/enroll/complete"},
		{http.MethodPost, "/provider/v1/auth/login"},
		{http.MethodPost, "/provider/v1/auth/logout"},
		{http.MethodGet, "/provider/v1/me"},
		{http.MethodGet, "/provider/v1/license"},
		{http.MethodGet, "/provider/v1/operators"},
		{http.MethodPost, "/provider/v1/operators"},
		{http.MethodPost, "/provider/v1/operators/{id}/status"},
		{http.MethodGet, "/provider/v1/tenants"},
		{http.MethodPost, "/provider/v1/tenants"},
		{http.MethodPatch, "/provider/v1/tenants/{id}"},
		{http.MethodPost, "/provider/v1/tenants/{id}/suspend"},
		{http.MethodPost, "/provider/v1/tenants/{id}/resume"},
		{http.MethodPost, "/provider/v1/tenants/{id}/offboard"},
		{http.MethodGet, "/provider/v1/fleet"},
		{http.MethodGet, "/provider/v1/tenants/provisioning"},
		{http.MethodPost, "/provider/v1/tenants/provisioning/{id}/abandon"},
		{http.MethodGet, "/provider/v1/breakglass"},
		{http.MethodPost, "/provider/v1/breakglass"},
		{http.MethodPost, "/provider/v1/breakglass/{id}/revoke"},
		{http.MethodGet, "/provider/v1/breakglass/{id}/results"},
		{http.MethodGet, "/provider/v1/audit"},
		{http.MethodGet, "/provider/v1/consent"},
		{http.MethodPost, "/provider/v1/consent/{id}"},
	}
	base = append(base, meteringRoutes()...)
	base = append(base, fairnessRoutes()...)
	base = append(base, governanceRoutes()...)
	return append(base, lifecycleRoutes()...)
}

// NewHandler builds the provider HTTP surface.
func NewHandler(svc *Service, sessions *Sessions, tenantAuth TenantAuth, log *slog.Logger, bootstrapToken string, secureCookies bool) *Handler {
	h := &Handler{
		svc: svc, sessions: sessions, tenantAuth: tenantAuth, log: log,
		bootstrapToken: bootstrapToken, secureCookies: secureCookies,
		mux: http.NewServeMux(),
	}
	// SEC-003: brute-force brake on the operator login, ON by construction
	// (zero values = the limiter's safe defaults: 5 failures / 1m window /
	// 1m lockout doubling to 1h).
	h.limiter = auth.NewLimiter(0, 0, 0)
	h.limiter.OnLockout = func(key string, failures int, lockout time.Duration) {
		log.Warn("provider auth lockout", "key", key, "failures", failures, "lockout", lockout.String())
		svc.RecordLoginLockout(context.Background(), key, failures, lockout)
	}

	// Public (they establish the operator session or the enrollment). Every
	// pattern registered WITHOUT an authorization wrapper must appear in
	// providerPublicAuthPatterns with its reason — the authz-chokepoint gate
	// holds the two in exact correspondence, so an unwrapped route cannot
	// appear silently and a stale exemption cannot linger.
	h.public("POST /provider/v1/auth/bootstrap", h.handleBootstrap)
	h.public("POST /provider/v1/auth/enroll/start", h.handleEnrollStart)
	h.public("POST /provider/v1/auth/enroll/complete", h.handleEnrollComplete)
	h.public("POST /provider/v1/auth/login", h.handleLogin)
	h.public("POST /provider/v1/auth/logout", h.handleLogout)

	// Operator-session routes. SoD: operator-level unless noted admin.
	h.handle("GET /provider/v1/me", h.asOperator("", h.handleMe))
	h.handle("GET /provider/v1/license", h.asOperator("", h.handleLicense))
	h.handle("GET /provider/v1/operators", h.asOperator(RoleAdmin, h.handleListOperators))
	h.handle("POST /provider/v1/operators", h.asOperator(RoleAdmin, h.handleCreateOperator))
	h.handle("POST /provider/v1/operators/{id}/status", h.asOperator(RoleAdmin, h.handleOperatorStatus))
	h.handle("GET /provider/v1/tenants", h.asOperator("", h.handleListTenants))
	h.handle("POST /provider/v1/tenants", h.asOperator("", h.handleProvision))
	h.handle("PATCH /provider/v1/tenants/{id}", h.asOperator("", h.handleConfigure))
	h.handle("POST /provider/v1/tenants/{id}/suspend", h.asOperator("", h.handleSuspend))
	h.handle("POST /provider/v1/tenants/{id}/resume", h.asOperator("", h.handleResume))
	h.handle("POST /provider/v1/tenants/{id}/offboard", h.asOperator("", h.handleOffboard))
	h.handle("GET /provider/v1/fleet", h.asOperator("", h.handleFleet))
	// Stranded provisioning attempts (S-fadcec95): list what never completed
	// with its last step, and offer an EXPLICIT abandon. Retry is the existing
	// idempotent POST /provider/v1/tenants with the same body.
	h.handle("GET /provider/v1/tenants/provisioning", h.asOperator("", h.handleListStrandedProvisions))
	h.handle("POST /provider/v1/tenants/provisioning/{id}/abandon", h.asOperator(RoleAdmin, h.handleAbandonProvision))
	h.handle("GET /provider/v1/breakglass", h.asOperator("", h.handleListGrants))
	h.handle("POST /provider/v1/breakglass", h.asOperator("", h.handleRequestGrant))
	h.handle("POST /provider/v1/breakglass/{id}/revoke", h.asOperator("", h.handleRevokeGrant))
	h.handle("GET /provider/v1/breakglass/{id}/results", h.asOperator("", h.handleGrantResults))
	// DPR-037: the plane's own activity log — a governance view, admin-only.
	h.handle("GET /provider/v1/audit", h.asOperator(RoleAdmin, h.handleListAudit))

	// Metering / usage / quotas (S-T3). Registered unconditionally; the
	// handlers answer not_found until WithMetering attaches the capability.
	h.handle("GET /provider/v1/fairness", h.asOperator("", h.handleFairnessView))
	h.handle("PUT /provider/v1/tenants/{id}/fairness", h.asOperator(RoleAdmin, h.handlePutFairness))
	h.handle("GET /provider/v1/tenants/{id}/governance", h.asOperator("", h.handleGovernanceView))
	h.handle("PUT /provider/v1/tenants/{id}/governance", h.asOperator(RoleAdmin, h.handlePutGovernance))
	h.handle("GET /provider/v1/usage", h.asOperator("", h.handleUsage))
	h.handle("GET /provider/v1/usage/export", h.asOperator("", h.handleUsageExport))
	h.handle("GET /provider/v1/tenants/{id}/quotas", h.asOperator("", h.handleGetQuotas))
	h.handle("PUT /provider/v1/tenants/{id}/quotas", h.asOperator(RoleAdmin, h.handlePutQuotas))

	// Verifiable erasure (S-T5; the engine is core — this is the operator
	// trigger). Admin SoD; slug-confirmed; audited.
	h.handle("POST /provider/v1/tenants/{id}/erase", h.asOperator(RoleAdmin, h.handleTenantErase))

	// Tenant-session routes (the consent leg).
	h.handle("GET /provider/v1/consent", h.asTenantAdmin(h.handleConsentList))
	h.handle("POST /provider/v1/consent/{id}", h.asTenantAdmin(h.handleConsentDecide))

	return h
}

// WithFairness attaches the S-T7 fairness views (enforcement is core; this
// is the operator surface over it).
func (h *Handler) WithFairness(f *Fairness) *Handler {
	if f != nil {
		h.fairness = f
	}
	return h
}

// WithGovernance attaches the S-EE3 governance capability.
func (h *Handler) WithGovernance(g *Governance) *Handler {
	if g != nil {
		h.governance = g
	}
	return h
}

// WithMetering attaches the S-T3 billing capability (the attach seam passes
// it only when the metering feature is licensed).
func (h *Handler) WithMetering(m *Metering) *Handler {
	if m != nil && m.Store != nil {
		h.metering = m
	}
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

type providerHandler func(w http.ResponseWriter, r *http.Request) error

func (h *Handler) handle(pattern string, fn providerHandler) {
	h.mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			h.writeErr(w, err)
		}
	}))
}

// asOperator authenticates the operator session; role != "" additionally
// requires that role (admins pass every role check — SoD is admin ⊃ operator).
func (h *Handler) asOperator(role string, fn func(w http.ResponseWriter, r *http.Request, op Operator) error) providerHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		op := h.sessions.ResolveContext(r.Context(), tokenFromRequest(r))
		if op == nil {
			return errUnauthorized
		}
		if op.Status != "active" {
			return errUnauthorized // a disabled operator's session is dead even pre-TTL
		}
		if role != "" && op.Role != role && op.Role != RoleAdmin {
			return errForbiddenRole
		}
		return fn(w, r, *op)
	}
}

// asTenantAdmin authenticates the TENANT session and applies the complete
// tenant-first, RBAC-then-ABAC decision to the consent permission. The resolved
// session tenant is authoritative for every downstream check — a request can
// never name another tenant. Authorization dependency failures fail closed.
func (h *Handler) asTenantAdmin(fn func(w http.ResponseWriter, r *http.Request, tenantID, userEmail string) error) providerHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if h.tenantAuth == nil {
			return errConsentNotConfigured
		}
		token := auth.TokenFromRequest(r)
		if token == "" {
			return errUnauthorized
		}
		sess, err := h.tenantAuth.ResolveSession(r.Context(), token)
		if err != nil || sess == nil {
			return errUnauthorized
		}
		principal, policies, err := h.tenantAuth.AuthorizationContext(r.Context(), sess)
		if err != nil {
			h.log.Warn("provider tenant authorization load failed",
				"tenant_id", sess.TenantID, "error", err.Error())
			return errConsentAuthorizationUnavailable
		}
		// Treat the session identity as authoritative and reject a malformed or
		// cross-tenant adapter result before RBAC/ABAC. This is defense in depth
		// above the adapter's tenant-scoped database transaction.
		if principal == nil || principal.TenantID != sess.TenantID || principal.UserID != sess.UserID {
			return errConsentAuthorizationUnavailable
		}
		resource := map[string]string{auth.ResourceTenantKey: sess.TenantID}
		if !auth.Authorize(principal, consentPermission, policies, resource) {
			return errForbiddenRole
		}
		return fn(w, r, sess.TenantID, principal.Email)
	}
}

// handleListStrandedProvisions serves the stranded-attempt list. The optional
// older_than filter (a Go duration) narrows it to attempts an operator is
// likely to act on; the default lists every in-flight attempt.
func (h *Handler) handleListStrandedProvisions(w http.ResponseWriter, r *http.Request, _ Operator) error {
	age := time.Duration(0)
	if v := strings.TrimSpace(r.URL.Query().Get("older_than")); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil || parsed < 0 {
			return errValidation{message: "older_than must be a non-negative Go duration (e.g. 30m)"}
		}
		age = parsed
	}
	items, err := h.svc.ListStrandedProvisions(r.Context(), age)
	if err != nil {
		return err
	}
	if items == nil {
		items = []StrandedProvision{}
	}
	return h.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleAbandonProvision tears down a stranded attempt's external state and
// removes its staging row. Admin-only and separately audited: it is a
// destructive lifecycle action on a half-created tenant.
func (h *Handler) handleAbandonProvision(w http.ResponseWriter, r *http.Request, op Operator) error {
	id := r.PathValue("id")
	if strings.TrimSpace(id) == "" {
		return errValidation{message: "provisioning id is required"}
	}
	if err := h.svc.AbandonProvision(r.Context(), op.Email, id); err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, map[string]any{"abandoned": true, "id": id})
}

// --- auth handlers ---

func (h *Handler) handleBootstrap(w http.ResponseWriter, r *http.Request) error {
	var in struct{ Token, Email, Name string }
	if err := decode(r, &in); err != nil {
		return err
	}
	op, enroll, err := h.svc.Bootstrap(r.Context(), h.bootstrapToken, in.Token, in.Email, in.Name)
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusCreated, map[string]any{"operator": op, "enroll_token": enroll})
}

func (h *Handler) handleEnrollStart(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Token string `json:"token"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	op, secret, uri, err := h.svc.EnrollStart(r.Context(), in.Token)
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, map[string]any{
		"email": op.Email, "totp_secret": secret, "otpauth_uri": uri,
	})
}

func (h *Handler) handleEnrollComplete(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	op, err := h.svc.EnrollComplete(r.Context(), in.Token, in.Password, in.TOTP)
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, map[string]any{"operator": op})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	// SEC-003: throttle BEFORE authentication — per source IP and per
	// account. A locked dimension refuses even a correct password.
	keys := []string{"pip:" + providerClientIP(r), "pacct:" + strings.ToLower(strings.TrimSpace(in.Email))}
	for _, k := range keys {
		if ok, retry := h.limiter.Allow(k); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
			return errRateLimited
		}
	}
	op, err := h.svc.Login(r.Context(), in.Email, in.Password, in.TOTP)
	if err != nil {
		for _, k := range keys {
			h.limiter.Fail(k)
		}
		return err
	}
	for _, k := range keys {
		h.limiter.Success(k)
	}
	// Successful authentication always changes the provider-domain session ID.
	// Consume the browser/CLI's prior token before minting its replacement; if
	// minting fails, losing the old high-privilege session is the safe outcome.
	h.sessions.RevokeContext(r.Context(), tokenFromRequest(r))
	token, err := h.sessions.IssueContext(r.Context(), op)
	if err != nil {
		return err
	}
	setCookie(w, token, h.secureCookies)
	return h.writeJSON(w, http.StatusOK, map[string]any{"operator": op, "token": token})
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) error {
	h.sessions.RevokeContext(r.Context(), tokenFromRequest(r))
	clearCookie(w, h.secureCookies)
	return h.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) handleMe(w http.ResponseWriter, _ *http.Request, op Operator) error {
	return h.writeJSON(w, http.StatusOK, map[string]any{"operator": op})
}

func (h *Handler) handleLicense(w http.ResponseWriter, _ *http.Request, _ Operator) error {
	return h.writeJSON(w, http.StatusOK, h.svc.lic.Info())
}

// --- operator management (admin) ---

func (h *Handler) handleListOperators(w http.ResponseWriter, r *http.Request, _ Operator) error {
	ops, err := h.svc.ListOperators(r.Context())
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, map[string]any{"items": ops})
}

func (h *Handler) handleCreateOperator(w http.ResponseWriter, r *http.Request, actor Operator) error {
	var in struct{ Email, Name, Role string }
	if err := decode(r, &in); err != nil {
		return err
	}
	op, enroll, err := h.svc.CreateOperator(r.Context(), actor.Email, in.Email, in.Name, in.Role)
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusCreated, map[string]any{"operator": op, "enroll_token": enroll})
}

func (h *Handler) handleOperatorStatus(w http.ResponseWriter, r *http.Request, actor Operator) error {
	var in struct {
		Status string `json:"status"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	id := r.PathValue("id")
	if err := h.svc.SetOperatorStatus(r.Context(), actor.Email, id, in.Status); err != nil {
		return err
	}
	if in.Status != "active" {
		h.sessions.RevokeOperatorContext(r.Context(), id) // disablement ends sessions immediately, on every replica
	}
	return h.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- tenant lifecycle ---

func (h *Handler) handleListTenants(w http.ResponseWriter, r *http.Request, _ Operator) error {
	ts, err := h.svc.ListTenants(r.Context())
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, map[string]any{"items": ts})
}

func (h *Handler) handleProvision(w http.ResponseWriter, r *http.Request, op Operator) error {
	var in struct {
		Slug           string `json:"slug"`
		Name           string `json:"name"`
		IsolationModel string `json:"isolation_model"`
		Residency      string `json:"residency"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	t, err := h.svc.Provision(r.Context(), op.Email, in.Slug, in.Name, in.IsolationModel, in.Residency)
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusCreated, t)
}

func (h *Handler) handleConfigure(w http.ResponseWriter, r *http.Request, op Operator) error {
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	t, err := h.svc.Configure(r.Context(), op.Email, r.PathValue("id"), in.Name)
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, t)
}

func (h *Handler) handleSuspend(w http.ResponseWriter, r *http.Request, op Operator) error {
	t, err := h.svc.Suspend(r.Context(), op.Email, r.PathValue("id"))
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, t)
}

func (h *Handler) handleResume(w http.ResponseWriter, r *http.Request, op Operator) error {
	t, err := h.svc.Resume(r.Context(), op.Email, r.PathValue("id"))
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, t)
}

func (h *Handler) handleOffboard(w http.ResponseWriter, r *http.Request, op Operator) error {
	t, err := h.svc.Offboard(r.Context(), op.Email, r.PathValue("id"))
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, t)
}

func (h *Handler) handleFleet(w http.ResponseWriter, r *http.Request, _ Operator) error {
	rows, err := h.svc.Fleet(r.Context())
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, map[string]any{"items": rows})
}

// --- break-glass ---

func (h *Handler) handleListGrants(w http.ResponseWriter, r *http.Request, _ Operator) error {
	gs, err := h.svc.ListGrants(r.Context())
	if err != nil {
		return err
	}
	now := h.svc.now()
	type withState struct {
		Grant
		StateNow string `json:"state"`
	}
	out := make([]withState, 0, len(gs))
	for _, g := range gs {
		out = append(out, withState{Grant: g, StateNow: g.State(now)})
	}
	return h.writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) handleRequestGrant(w http.ResponseWriter, r *http.Request, op Operator) error {
	var in struct {
		TenantID   string `json:"tenant_id"`
		Reason     string `json:"reason"`
		TTLMinutes int    `json:"ttl_minutes"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	g, err := h.svc.RequestBreakGlass(r.Context(), op, in.TenantID, in.Reason, time.Duration(in.TTLMinutes)*time.Minute)
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusCreated, g)
}

func (h *Handler) handleRevokeGrant(w http.ResponseWriter, r *http.Request, op Operator) error {
	g, err := h.svc.Revoke(r.Context(), op.Email, r.PathValue("id"))
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, g)
}

func (h *Handler) handleGrantResults(w http.ResponseWriter, r *http.Request, op Operator) error {
	data, err := h.svc.BreakGlassResults(r.Context(), op, r.PathValue("id"))
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, map[string]any{"items": data})
}

// --- tenant consent ---

// handleListAudit (DPR-037) pages the provider/break-glass audit stream: every
// bootstrap, login, lockout, operator change, tenant lifecycle step,
// break-glass request/consent/access/revoke and provisioning outcome this
// plane recorded. Default is oldest-first after `after`; `order=desc` walks
// newest-first before `before` (0 = head), which is what an activity view
// wants. actor/action/target are case-insensitive substring filters. Reads
// never append to the stream they page.
func (h *Handler) handleListAudit(w http.ResponseWriter, r *http.Request, _ Operator) error {
	q := r.URL.Query()
	newestFirst := q.Get("order") == "desc"
	cursorParam := "after"
	if newestFirst {
		cursorParam = "before"
	}
	cursor, err := auditQueryInt64(q.Get(cursorParam))
	if err != nil {
		return validationError("provider: " + cursorParam + " must be a non-negative integer")
	}
	limit, err := auditQueryInt64(q.Get("limit"))
	if err != nil {
		return validationError("provider: limit must be a non-negative integer")
	}
	if limit == 0 {
		limit = 50
	}
	filter := coreaudit.Filter{
		Actor:  q.Get("actor"),
		Action: q.Get("action"),
		Target: q.Get("target"),
	}
	events, err := h.svc.ListAudit(r.Context(), cursor, int(min(limit, coreaudit.MaxExportPageSize)), filter, newestFirst)
	if err != nil {
		return err
	}
	var next int64
	if n := len(events); n > 0 {
		next = events[n-1].Seq
	}
	order := "asc"
	if newestFirst {
		order = "desc"
	}
	return h.writeJSON(w, http.StatusOK, map[string]any{"items": events, "next": next, "order": order})
}

func auditQueryInt64(raw string) (int64, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("not a non-negative integer")
	}
	return n, nil
}

func (h *Handler) handleConsentList(w http.ResponseWriter, r *http.Request, tenantID, _ string) error {
	gs, err := h.svc.PendingForTenant(r.Context(), tenantID)
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, map[string]any{"items": gs})
}

func (h *Handler) handleConsentDecide(w http.ResponseWriter, r *http.Request, tenantID, userEmail string) error {
	var in struct {
		Decision string `json:"decision"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	if in.Decision != "approve" && in.Decision != "deny" {
		return errBadDecision
	}
	g, err := h.svc.Consent(r.Context(), tenantID, r.PathValue("id"), userEmail, in.Decision == "approve")
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, g)
}

// --- plumbing ---

var (
	errUnauthorized = errors.New("provider: operator authentication required")
	// errRateLimited refuses a throttled/locked login dimension (SEC-003).
	errRateLimited          = errors.New("provider: too many login attempts (locked, backing off)")
	errForbiddenRole        = errors.New("provider: insufficient role")
	errConsentNotConfigured = errors.New("provider: tenant-session auth is not configured on this deployment")
	// Policy/subject/RBAC load failures are operational failures, not missing
	// permissions. They still deny the request, but answer 503 so operators can
	// distinguish an unavailable policy store from an intentional ABAC deny.
	errConsentAuthorizationUnavailable = errors.New("provider: tenant authorization is temporarily unavailable")
	errBadDecision                     = validationError("provider: decision must be approve or deny")
)

func decode(r *http.Request, v any) error {
	if err := httpbody.DecodeHTTPJSONStrict(nil, r, 1<<20, v); err != nil {
		return errBadJSON{err}
	}
	return nil
}

type errBadJSON struct{ err error }

func (e errBadJSON) Error() string { return "provider: invalid request body: " + e.err.Error() }

// errValidation is the explicit public 400 class. A message prefix is never an
// authorization to expose an error: only construction as this package-private
// domain type (or errBadJSON above) lets validation detail cross the HTTP
// boundary. Storage, crypto, audit, and other wrapped dependency failures remain
// unknown errors and are therefore redacted 500s.
type errValidation struct{ message string }

func (e errValidation) Error() string { return e.message }

func validationError(message string) error { return errValidation{message: message} }

func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// providerClientIP is the throttle key source: the transport RemoteAddr.
// Forwarded headers are deliberately NOT trusted (spoofable) — same stance as
// the tenant limiter (U-024); a fronting ingress that should count real client
// IPs must rewrite the connection source (PROXY protocol), not a header.
func providerClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// writeErr maps service errors onto the core error envelope shape
// ({"error":{"code","message"}}), so both surfaces speak one dialect.
func (h *Handler) writeErr(w http.ResponseWriter, err error) {
	code, status := "internal", http.StatusInternalServerError
	switch {
	case errors.Is(err, errRateLimited):
		code, status = "rate_limited", http.StatusTooManyRequests
	case errors.Is(err, errUnauthorized):
		code, status = "unauthorized", http.StatusUnauthorized
	case errors.Is(err, errForbiddenRole), errors.Is(err, ErrForbidden), errors.Is(err, ErrNotGrantee):
		code, status = "forbidden", http.StatusForbidden
	case errors.Is(err, ErrNotConsented):
		code, status = "breakglass_not_active", http.StatusForbidden
	case errors.Is(err, ErrTenantIRKeyMissing):
		// DPR-036: a deployment precondition the operator can fix (install
		// the tenant's IR public key), not an internal failure — say so.
		code, status = "ir_key_unavailable", http.StatusConflict
	case errors.Is(err, ErrReadOnly):
		code, status = "license_read_only", http.StatusForbidden
	case errors.Is(err, ErrBandExhausted):
		code, status = "tenant_band_exhausted", http.StatusForbidden
	case errors.Is(err, ErrNotFound):
		code, status = "not_found", http.StatusNotFound
	case errors.Is(err, ErrConflict):
		code, status = "conflict", http.StatusConflict
	case errors.Is(err, errConsentNotConfigured):
		code, status = "not_configured", http.StatusServiceUnavailable
	case errors.Is(err, ErrAuditReadUnavailable):
		code, status = "audit_read_unavailable", http.StatusServiceUnavailable
	case errors.Is(err, errConsentAuthorizationUnavailable):
		code, status = "authorization_unavailable", http.StatusServiceUnavailable
	default:
		var bad errBadJSON
		var validation errValidation
		if errors.As(err, &bad) || errors.As(err, &validation) {
			code, status = "bad_request", http.StatusBadRequest
		}
	}
	message := err.Error()
	if status >= 500 {
		h.log.Error("provider request failed", "error", err)
		message = "internal error"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": message}})
}

// providerPublicAuthPatterns is the CLOSED set of provider routes deliberately
// registered without an operator/tenant-admin authorization wrapper, each with
// the reason it is public. The authz-chokepoint gate (S-6357f747) fails if a
// route is registered unwrapped without an entry here, or if an entry stops
// matching a registration.
// public registers a deliberately session-less route. The pattern MUST carry
// an entry in providerPublicAuthPatterns — registering an undeclared public
// route is a programmer error and panics at construction, and the
// authz-chokepoint gate enforces the same correspondence statically.
func (h *Handler) public(pattern string, fn providerHandler) {
	if _, ok := providerPublicAuthPatterns[pattern]; !ok {
		panic("provider route " + pattern + " registered as public without an entry in providerPublicAuthPatterns")
	}
	h.handle(pattern, fn)
}

var providerPublicAuthPatterns = map[string]string{
	"POST /provider/v1/auth/bootstrap":       "first-operator bootstrap: no operator exists yet to authenticate",
	"POST /provider/v1/auth/enroll/start":    "operator enrollment begins pre-session (token-gated inside)",
	"POST /provider/v1/auth/enroll/complete": "operator enrollment completes pre-session (token-gated inside)",
	"POST /provider/v1/auth/login":           "establishes the operator session (rate-limited + lockout)",
	"POST /provider/v1/auth/logout":          "tears down a session by its own token; no privilege exercised",
}
