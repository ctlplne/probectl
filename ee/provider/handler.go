// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).
// See ee/doc.go for the boundary rules every ee/ file observes.

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
)

// The provider HTTP surface, mounted by core at /provider/ (an opaque
// http.Handler — core never imports this package; the licensed build attaches
// it at the main.go seam). Operator authn is the handler's own; tenant
// sessions and the dev principal mean nothing here, with ONE deliberate
// exception: the consent endpoints, which authenticate the TENANT session —
// consent belongs to the tenant, not to operators.

// TenantAuth resolves a tenant session + its permissions (the consent leg).
// The production adapter wraps auth.Manager + the RBAC PermissionLoader.
type TenantAuth interface {
	ResolveSession(ctx context.Context, token string) (*auth.Session, error)
	Permissions(ctx context.Context, tenantID, userID string) ([]string, error)
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

	bootstrapToken string
	secureCookies  bool

	mux *http.ServeMux
}

// RouteDecl is one provider route (kept as a table so the provider OpenAPI
// self-test can assert spec completeness, mirroring the core gate).
type RouteDecl struct {
	Method  string
	Pattern string
}

// Routes is the provider plane's route table.
func Routes() []RouteDecl {
	return []RouteDecl{
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
		{http.MethodGet, "/provider/v1/breakglass"},
		{http.MethodPost, "/provider/v1/breakglass"},
		{http.MethodPost, "/provider/v1/breakglass/{id}/revoke"},
		{http.MethodGet, "/provider/v1/breakglass/{id}/results"},
		{http.MethodGet, "/provider/v1/consent"},
		{http.MethodPost, "/provider/v1/consent/{id}"},
	}
}

// NewHandler builds the provider HTTP surface.
func NewHandler(svc *Service, sessions *Sessions, tenantAuth TenantAuth, log *slog.Logger, bootstrapToken string, secureCookies bool) *Handler {
	h := &Handler{
		svc: svc, sessions: sessions, tenantAuth: tenantAuth, log: log,
		bootstrapToken: bootstrapToken, secureCookies: secureCookies,
		mux: http.NewServeMux(),
	}

	// Public (they establish the operator session or the enrollment).
	h.handle("POST /provider/v1/auth/bootstrap", h.handleBootstrap)
	h.handle("POST /provider/v1/auth/enroll/start", h.handleEnrollStart)
	h.handle("POST /provider/v1/auth/enroll/complete", h.handleEnrollComplete)
	h.handle("POST /provider/v1/auth/login", h.handleLogin)
	h.handle("POST /provider/v1/auth/logout", h.handleLogout)

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
	h.handle("GET /provider/v1/breakglass", h.asOperator("", h.handleListGrants))
	h.handle("POST /provider/v1/breakglass", h.asOperator("", h.handleRequestGrant))
	h.handle("POST /provider/v1/breakglass/{id}/revoke", h.asOperator("", h.handleRevokeGrant))
	h.handle("GET /provider/v1/breakglass/{id}/results", h.asOperator("", h.handleGrantResults))

	// Tenant-session routes (the consent leg).
	h.handle("GET /provider/v1/consent", h.asTenantAdmin(h.handleConsentList))
	h.handle("POST /provider/v1/consent/{id}", h.asTenantAdmin(h.handleConsentDecide))

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
		op := h.sessions.Resolve(tokenFromRequest(r))
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

// asTenantAdmin authenticates the TENANT session (core auth) and requires the
// consent permission within that tenant. The resolved tenant is authoritative
// for every downstream check — a request can never name another tenant.
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
		perms, err := h.tenantAuth.Permissions(r.Context(), sess.TenantID, sess.UserID)
		if err != nil {
			return errUnauthorized
		}
		allowed := false
		for _, p := range perms {
			if p == consentPermission {
				allowed = true
				break
			}
		}
		if !allowed {
			return errForbiddenRole
		}
		return fn(w, r, sess.TenantID, sess.Email)
	}
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
	op, err := h.svc.Login(r.Context(), in.Email, in.Password, in.TOTP)
	if err != nil {
		return err
	}
	token, err := h.sessions.Issue(op)
	if err != nil {
		return err
	}
	setCookie(w, token, h.secureCookies)
	return h.writeJSON(w, http.StatusOK, map[string]any{"operator": op, "token": token})
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) error {
	h.sessions.Revoke(tokenFromRequest(r))
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
		h.sessions.RevokeOperator(id) // disablement ends sessions immediately
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
	var in struct{ Slug, Name string }
	if err := decode(r, &in); err != nil {
		return err
	}
	t, err := h.svc.Provision(r.Context(), op.Email, in.Slug, in.Name)
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
	errUnauthorized         = errors.New("provider: operator authentication required")
	errForbiddenRole        = errors.New("provider: insufficient role")
	errConsentNotConfigured = errors.New("provider: tenant-session auth is not configured on this deployment")
	errBadDecision          = errors.New("provider: decision must be approve or deny")
)

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errBadJSON{err}
	}
	return nil
}

type errBadJSON struct{ err error }

func (e errBadJSON) Error() string { return "provider: invalid request body: " + e.err.Error() }

func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// writeErr maps service errors onto the core error envelope shape
// ({"error":{"code","message"}}), so both surfaces speak one dialect.
func (h *Handler) writeErr(w http.ResponseWriter, err error) {
	code, status := "internal", http.StatusInternalServerError
	switch {
	case errors.Is(err, errUnauthorized):
		code, status = "unauthorized", http.StatusUnauthorized
	case errors.Is(err, errForbiddenRole), errors.Is(err, ErrForbidden), errors.Is(err, ErrNotGrantee):
		code, status = "forbidden", http.StatusForbidden
	case errors.Is(err, ErrNotConsented):
		code, status = "breakglass_not_active", http.StatusForbidden
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
	default:
		var bad errBadJSON
		if errors.As(err, &bad) || strings.HasPrefix(err.Error(), "provider: ") {
			code, status = "bad_request", http.StatusBadRequest
		}
	}
	if status >= 500 {
		h.log.Error("provider request failed", "error", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": err.Error()}})
}
