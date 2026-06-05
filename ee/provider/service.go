// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).
// See ee/doc.go for the boundary rules every ee/ file observes.

package provider

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/license"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// AuditSink receives provider-plane audit events. The production sink wraps
// audit.ProviderAppend (the separate, equally tamper-evident provider stream —
// CLAUDE.md §7 guardrail 7); tests capture events in memory.
type AuditSink interface {
	Append(ctx context.Context, actor, action, target string, data map[string]any) error
}

// TelemetryReader is the ONLY telemetry surface break-glass can reach in S-T1:
// the latest-results read model. The production adapter wraps
// control.LatestResults; the interface keeps the service unit-testable and the
// blast radius explicit.
type TelemetryReader interface {
	LatestResults(tenantID string) any
}

// Service errors, mapped to HTTP codes by the handler.
var (
	ErrReadOnly      = errors.New("provider: license expired — the provider plane is read-only (new tenants/config are blocked; running telemetry is unaffected)")
	ErrBandExhausted = errors.New("provider: licensed tenant band exhausted")
	ErrNotConsented  = errors.New("provider: break-glass grant is not active (missing consent, expired, denied, or revoked)")
	ErrNotGrantee    = errors.New("provider: break-glass grants are operator-bound — only the requesting operator may use one")
	ErrForbidden     = errors.New("provider: forbidden")
)

// SiloOps is the S-T2 isolation seam: provisioning/teardown of a tenant's
// isolated stores plus residency validation. Implemented by silo.Provisioner;
// nil when the deployment is not licensed for siloed_isolation (then only
// pooled tenants can be provisioned).
type SiloOps interface {
	Provision(ctx context.Context, tenantID, residency string, model tenancy.IsolationModel) error
	Teardown(ctx context.Context, tenantID, residency string, model tenancy.IsolationModel) error
	ValidResidency(name string) bool
	Planes() []string
}

// Service implements the provider plane's business rules over Store. Every
// mutation and every break-glass access is written to the provider audit
// stream before the call returns.
type Service struct {
	store     Store
	audit     AuditSink
	lic       *license.Manager
	telemetry TelemetryReader
	envelope  *crypto.Envelope
	now       func() time.Time

	maxGrantTTL time.Duration

	// S-T2: nil = pooled-only (the siloed_isolation feature is not licensed).
	silo SiloOps
	// routerInvalidate drops the isolation router's registry cache after a
	// lifecycle change, so new/changed tenants route correctly at once.
	routerInvalidate func()
}

// NewService wires the provider service. envelope is required (TOTP secrets
// are sealed at rest); license is required (the plane is built only when
// licensed, and its Mode drives read-only degrade).
func NewService(store Store, sink AuditSink, lic *license.Manager, telemetry TelemetryReader, env *crypto.Envelope, maxGrantTTL time.Duration) (*Service, error) {
	if store == nil || sink == nil || lic == nil || env == nil {
		return nil, errors.New("provider: store, audit sink, license, and envelope are all required")
	}
	if maxGrantTTL <= 0 {
		maxGrantTTL = 4 * time.Hour
	}
	return &Service{
		store: store, audit: sink, lic: lic, telemetry: telemetry,
		envelope: env, now: time.Now, maxGrantTTL: maxGrantTTL,
	}, nil
}

// WithClock overrides time (tests).
func (s *Service) WithClock(now func() time.Time) *Service {
	s.now = now
	return s
}

// WithSilo attaches the S-T2 isolation capability (the attach seam passes it
// only when the license grants siloed_isolation) and the router-cache
// invalidation hook.
func (s *Service) WithSilo(ops SiloOps, invalidate func()) *Service {
	s.silo = ops
	s.routerInvalidate = invalidate
	return s
}

// CheckWritable exposes the read-only-degrade gate for surfaces (S-T3 quota
// writes) that live outside this file.
func (s *Service) CheckWritable() error { return s.writable() }

// RecordQuotaChange audits a quota update on the provider stream.
func (s *Service) RecordQuotaChange(ctx context.Context, actor, tenantID string, maxAgents, maxTests *int) error {
	data := map[string]any{}
	if maxAgents != nil {
		data["max_agents"] = *maxAgents
	}
	if maxTests != nil {
		data["max_tests"] = *maxTests
	}
	return s.audit.Append(ctx, actor, "provider.quota_set", tenantID, data)
}

// RecordBrandingChange audits a white-label update on the provider stream.
func (s *Service) RecordBrandingChange(ctx context.Context, actor, target, customDomain string) error {
	data := map[string]any{}
	if customDomain != "" {
		data["custom_domain"] = customDomain
	}
	return s.audit.Append(ctx, actor, "provider.branding_set", target, data)
}

func (s *Service) invalidateRouter() {
	if s.routerInvalidate != nil {
		s.routerInvalidate()
	}
}

// writable returns ErrReadOnly when the license has degraded past grace
// (S-T0 ladder): GETs keep working, mutations stop, telemetry never breaks.
func (s *Service) writable() error {
	if s.lic.Mode(license.FeatureProviderPlane) != license.ModeEnabled {
		return ErrReadOnly
	}
	return nil
}

// --- Operator management (SoD: admin-only at the handler) ---

// CreateOperator registers an operator and returns the one-time enrollment
// token (shown exactly once; only its hash is stored).
func (s *Service) CreateOperator(ctx context.Context, actor, email, name, role string) (Operator, string, error) {
	if err := s.writable(); err != nil {
		return Operator{}, "", err
	}
	if role != RoleAdmin && role != RoleOperator {
		return Operator{}, "", fmt.Errorf("provider: role must be %q or %q", RoleAdmin, RoleOperator)
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !strings.Contains(email, "@") {
		return Operator{}, "", errors.New("provider: a valid operator email is required")
	}
	token, err := randomToken()
	if err != nil {
		return Operator{}, "", err
	}
	op, err := s.store.CreateOperator(ctx, Operator{Email: email, Name: name, Role: role, Status: "disabled"}, crypto.Hash([]byte(token)))
	if err != nil {
		return Operator{}, "", err
	}
	if err := s.audit.Append(ctx, actor, "provider.operator_create", op.ID, map[string]any{"email": email, "role": role}); err != nil {
		return Operator{}, "", err
	}
	return op, token, nil
}

// Bootstrap creates the FIRST admin from the deployment's bootstrap token.
// It works only while zero operators exist; afterwards the token is inert.
func (s *Service) Bootstrap(ctx context.Context, configuredToken, presentedToken, email, name string) (Operator, string, error) {
	if configuredToken == "" {
		return Operator{}, "", errors.New("provider: bootstrap is not configured (set PROBECTL_PROVIDER_BOOTSTRAP_TOKEN)")
	}
	if !crypto.ConstantTimeEqual([]byte(configuredToken), []byte(presentedToken)) {
		return Operator{}, "", ErrForbidden
	}
	n, err := s.store.CountOperators(ctx)
	if err != nil {
		return Operator{}, "", err
	}
	if n > 0 {
		return Operator{}, "", errors.New("provider: bootstrap is single-use — operators already exist")
	}
	token, err := randomToken()
	if err != nil {
		return Operator{}, "", err
	}
	op, err := s.store.CreateOperator(ctx, Operator{Email: strings.ToLower(email), Name: name, Role: RoleAdmin, Status: "disabled"}, crypto.Hash([]byte(token)))
	if err != nil {
		return Operator{}, "", err
	}
	if err := s.audit.Append(ctx, "bootstrap", "provider.bootstrap", op.ID, map[string]any{"email": op.Email}); err != nil {
		return Operator{}, "", err
	}
	return op, token, nil
}

// EnrollStart exchanges a valid enrollment token for the TOTP binding: the
// secret is generated server-side, sealed at rest, and returned ONCE (over
// TLS) for the operator's authenticator app.
func (s *Service) EnrollStart(ctx context.Context, enrollToken string) (Operator, string, string, error) {
	op, err := s.store.OperatorByEnrollHash(ctx, crypto.Hash([]byte(enrollToken)))
	if err != nil {
		return Operator{}, "", "", ErrForbidden // an invalid token gets no detail
	}
	b32, raw, err := crypto.GenerateTOTPSecret()
	if err != nil {
		return Operator{}, "", "", err
	}
	sealed, err := s.envelope.Seal(ctx, raw, []byte("provider-totp:"+op.ID))
	if err != nil {
		return Operator{}, "", "", err
	}
	if err := s.store.SetOperatorTOTP(ctx, op.ID, sealed); err != nil {
		return Operator{}, "", "", err
	}
	return *op, b32, crypto.TOTPURI("probectl provider", op.Email, b32), nil
}

// EnrollComplete verifies the operator's first TOTP code (proving the
// authenticator is bound), sets the password, and activates the account.
func (s *Service) EnrollComplete(ctx context.Context, enrollToken, password, totpCode string) (Operator, error) {
	op, err := s.store.OperatorByEnrollHash(ctx, crypto.Hash([]byte(enrollToken)))
	if err != nil {
		return Operator{}, ErrForbidden
	}
	if len(password) < 12 {
		return Operator{}, errors.New("provider: operator passwords must be at least 12 characters")
	}
	_, cred, err := s.store.OperatorByEmail(ctx, op.Email)
	if err != nil {
		return Operator{}, err
	}
	secret, err := s.envelope.Open(ctx, cred.TOTP, []byte("provider-totp:"+op.ID))
	if err != nil {
		return Operator{}, fmt.Errorf("provider: unseal totp: %w", err)
	}
	if !crypto.VerifyTOTP(secret, totpCode, s.now()) {
		return Operator{}, ErrForbidden
	}
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return Operator{}, err
	}
	if err := s.store.ActivateOperator(ctx, op.ID, hash); err != nil {
		return Operator{}, err
	}
	if err := s.audit.Append(ctx, op.Email, "provider.operator_enrolled", op.ID, nil); err != nil {
		return Operator{}, err
	}
	op.Enrolled, op.Status = true, "active"
	return *op, nil
}

// Login verifies email + password + TOTP (MFA is mandatory in the provider
// domain — there is no password-only path). Failures are uniform: no signal
// distinguishes a wrong password from a wrong code or an unknown email.
func (s *Service) Login(ctx context.Context, email, password, totpCode string) (Operator, error) {
	op, cred, err := s.store.OperatorByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if err != nil || op.Status != "active" || !op.Enrolled {
		return Operator{}, ErrForbidden
	}
	if !crypto.VerifyPassword(cred.PasswordHash, password) {
		return Operator{}, ErrForbidden
	}
	secret, err := s.envelope.Open(ctx, cred.TOTP, []byte("provider-totp:"+op.ID))
	if err != nil {
		return Operator{}, ErrForbidden
	}
	if !crypto.VerifyTOTP(secret, totpCode, s.now()) {
		return Operator{}, ErrForbidden
	}
	if err := s.audit.Append(ctx, op.Email, "provider.login", op.ID, nil); err != nil {
		return Operator{}, err
	}
	return *op, nil
}

// SetOperatorStatus enables/disables an operator (admin SoD at the handler).
func (s *Service) SetOperatorStatus(ctx context.Context, actor, id, status string) error {
	if err := s.writable(); err != nil {
		return err
	}
	if status != "active" && status != "disabled" {
		return errors.New("provider: status must be active or disabled")
	}
	if err := s.store.SetOperatorStatus(ctx, id, status); err != nil {
		return err
	}
	return s.audit.Append(ctx, actor, "provider.operator_status", id, map[string]any{"status": status})
}

// ListOperators returns the operator roster.
func (s *Service) ListOperators(ctx context.Context) ([]Operator, error) {
	return s.store.ListOperators(ctx)
}

// --- Tenant lifecycle ---

// Provision creates a tenant, enforcing the licensed tenant band (S-T0's
// TenantBand claim is consumed here): provisioning beyond the band fails
// loudly; existing tenants are never affected. The isolation model (S-T2)
// defaults to pooled; siloed/hybrid require the siloed_isolation capability
// and provision the tenant's isolated stores before the call returns.
func (s *Service) Provision(ctx context.Context, actor, slug, name, isolationModel, residency string) (Tenant, error) {
	if err := s.writable(); err != nil {
		return Tenant{}, err
	}
	if !ValidSlug(slug) {
		return Tenant{}, errors.New("provider: slug must be lowercase alphanumeric/hyphen, 2-63 chars")
	}
	if isolationModel == "" {
		isolationModel = string(tenancy.IsolationPooled)
	}
	if !tenancy.ValidIsolationModel(isolationModel) {
		return Tenant{}, errors.New("provider: isolation_model must be pooled, siloed, or hybrid")
	}
	model := tenancy.IsolationModel(isolationModel)
	if model != tenancy.IsolationPooled {
		if s.silo == nil {
			return Tenant{}, fmt.Errorf("%w: siloed/hybrid isolation requires the siloed_isolation license feature", ErrForbidden)
		}
		if !s.silo.ValidResidency(residency) {
			return Tenant{}, fmt.Errorf("provider: unknown residency %q (configured: %s)", residency, strings.Join(s.silo.Planes(), ", "))
		}
	} else if residency != "" {
		return Tenant{}, errors.New("provider: residency targeting requires a siloed or hybrid tenant")
	}
	if band := s.lic.TenantBand(); band > 0 {
		n, err := s.store.CountActiveTenants(ctx)
		if err != nil {
			return Tenant{}, err
		}
		if n >= band {
			return Tenant{}, fmt.Errorf("%w: %d of %d in use", ErrBandExhausted, n, band)
		}
	}
	t, err := s.store.CreateTenant(ctx, slug, strings.TrimSpace(name), isolationModel, residency)
	if err != nil {
		return Tenant{}, err
	}
	// Create the isolated stores BEFORE announcing success: a siloed tenant
	// must never exist without its silo (the pooled fall-through hazard).
	if model != tenancy.IsolationPooled {
		if err := s.silo.Provision(ctx, t.ID, residency, model); err != nil {
			return Tenant{}, fmt.Errorf("silo provisioning failed (re-run provision to complete): %w", err)
		}
	}
	s.invalidateRouter()
	if err := s.audit.Append(ctx, actor, "provider.tenant_provision", t.ID, map[string]any{
		"slug": slug, "name": name, "isolation_model": isolationModel, "residency": residency,
	}); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// Configure renames a tenant.
func (s *Service) Configure(ctx context.Context, actor, id, name string) (Tenant, error) {
	if err := s.writable(); err != nil {
		return Tenant{}, err
	}
	t, err := s.store.RenameTenant(ctx, id, strings.TrimSpace(name))
	if err != nil {
		return Tenant{}, err
	}
	if err := s.audit.Append(ctx, actor, "provider.tenant_configure", id, map[string]any{"name": name}); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// Suspend stops a tenant's users at the API (the core lifecycle gate); data
// and ingestion are untouched — suspension is reversible, never destructive.
func (s *Service) Suspend(ctx context.Context, actor, id string) (Tenant, error) {
	return s.setStatus(ctx, actor, id, "suspended", "provider.tenant_suspend")
}

// Resume reactivates a suspended tenant.
func (s *Service) Resume(ctx context.Context, actor, id string) (Tenant, error) {
	return s.setStatus(ctx, actor, id, "active", "provider.tenant_resume")
}

// Offboard marks a tenant offboarding: API access stops and the tenant leaves
// the licensed band. For siloed/hybrid tenants the isolated stores are torn
// down (S-T2: "offboarding removes a siloed tenant's stores" — they are
// per-tenant containers). POOLED rows are NOT touched: their export +
// verifiable deletion are S-T5 (a compliance right, deliberately core).
// Idempotent: a failed teardown is re-run by calling offboard again.
func (s *Service) Offboard(ctx context.Context, actor, id string) (Tenant, error) {
	t, err := s.setStatus(ctx, actor, id, "offboarding", "provider.tenant_offboard")
	if err != nil {
		return Tenant{}, err
	}
	model := tenancy.IsolationModel(t.IsolationModel)
	if model == tenancy.IsolationSiloed || model == tenancy.IsolationHybrid {
		if s.silo == nil {
			return Tenant{}, errors.New("provider: tenant has isolated stores but the silo capability is not attached")
		}
		if err := s.silo.Teardown(ctx, t.ID, t.Residency, model); err != nil {
			return Tenant{}, fmt.Errorf("silo teardown failed (re-run offboard to retry): %w", err)
		}
		if err := s.audit.Append(ctx, actor, "provider.tenant_silo_teardown", t.ID, map[string]any{
			"isolation_model": t.IsolationModel, "residency": t.Residency,
		}); err != nil {
			return Tenant{}, err
		}
	}
	return t, nil
}

func (s *Service) setStatus(ctx context.Context, actor, id, status, action string) (Tenant, error) {
	if err := s.writable(); err != nil {
		return Tenant{}, err
	}
	t, err := s.store.SetTenantStatus(ctx, id, status)
	if err != nil {
		return Tenant{}, err
	}
	s.invalidateRouter()
	if err := s.audit.Append(ctx, actor, action, id, map[string]any{"slug": t.Slug}); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// ListTenants returns the tenant inventory.
func (s *Service) ListTenants(ctx context.Context) ([]Tenant, error) { return s.store.ListTenants(ctx) }

// Fleet returns per-tenant agent health across all tenants — operational
// metadata only (the storage role cannot read telemetry tables at all).
func (s *Service) Fleet(ctx context.Context) ([]TenantFleet, error) { return s.store.FleetSummary(ctx) }

// --- Break-glass ---

// RequestBreakGlass opens a PENDING grant. It is unusable until a tenant
// admin consents; TTLs are capped; the request itself is audited.
func (s *Service) RequestBreakGlass(ctx context.Context, op Operator, tenantID, reason string, ttl time.Duration) (Grant, error) {
	if err := s.writable(); err != nil {
		return Grant{}, err
	}
	if strings.TrimSpace(reason) == "" {
		return Grant{}, errors.New("provider: break-glass requires a reason")
	}
	if ttl <= 0 || ttl > s.maxGrantTTL {
		return Grant{}, fmt.Errorf("provider: ttl must be within (0, %s]", s.maxGrantTTL)
	}
	now := s.now()
	g, err := s.store.CreateGrant(ctx, Grant{
		OperatorID: op.ID, OperatorEmail: op.Email, TenantID: tenantID,
		Reason: reason, Scope: "read", GrantedBy: op.Email,
		GrantedAt: now, ExpiresAt: now.Add(ttl),
	})
	if err != nil {
		return Grant{}, err
	}
	if err := s.audit.Append(ctx, op.Email, "provider.breakglass_request", g.ID, map[string]any{
		"tenant": tenantID, "reason": reason, "expires_at": g.ExpiresAt.UTC().Format(time.RFC3339),
	}); err != nil {
		return Grant{}, err
	}
	return g, nil
}

// Consent records a tenant admin's decision. by identifies the consenting
// tenant user; tenantID must match the grant (a tenant can only decide its
// own grants — checked here AND at the handler's session resolution).
func (s *Service) Consent(ctx context.Context, tenantID, grantID, by string, approve bool) (Grant, error) {
	g, err := s.store.GetGrant(ctx, grantID)
	if err != nil {
		return Grant{}, err
	}
	if g.TenantID != tenantID {
		return Grant{}, ErrForbidden // never confirm another tenant's grant exists
	}
	if g.State(s.now()) != GrantPending {
		return Grant{}, fmt.Errorf("provider: grant is %s, not pending", g.State(s.now()))
	}
	var out *Grant
	action := "provider.breakglass_consent"
	if approve {
		out, err = s.store.ConsentGrant(ctx, grantID, by, s.now())
	} else {
		action = "provider.breakglass_deny"
		out, err = s.store.DenyGrant(ctx, grantID, by, s.now())
	}
	if err != nil {
		return Grant{}, err
	}
	if err := s.audit.Append(ctx, by, action, grantID, map[string]any{"tenant": tenantID}); err != nil {
		return Grant{}, err
	}
	return *out, nil
}

// Revoke ends a grant early (operator-side; also reachable to admins).
func (s *Service) Revoke(ctx context.Context, actor, grantID string) (Grant, error) {
	g, err := s.store.RevokeGrant(ctx, grantID, actor, s.now())
	if err != nil {
		return Grant{}, err
	}
	if err := s.audit.Append(ctx, actor, "provider.breakglass_revoke", grantID, map[string]any{"tenant": g.TenantID}); err != nil {
		return Grant{}, err
	}
	return *g, nil
}

// ListGrants returns all grants (operator console).
func (s *Service) ListGrants(ctx context.Context) ([]Grant, error) { return s.store.ListGrants(ctx) }

// PendingForTenant lists a tenant's pending grants (the consent surface).
func (s *Service) PendingForTenant(ctx context.Context, tenantID string) ([]Grant, error) {
	all, err := s.store.ListGrantsForTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]Grant, 0, len(all))
	for _, g := range all {
		if g.State(now) == GrantPending {
			out = append(out, g)
		}
	}
	return out, nil
}

// BreakGlassResults is THE telemetry access path — the only one. It requires
// an ACTIVE (consented, unexpired, unrevoked) grant owned by the calling
// operator, increments the grant's use counter, and writes a provider audit
// record for EVERY access before any data is returned (guardrail 1: explicit,
// time-bounded, tenant-consented, separately audited).
func (s *Service) BreakGlassResults(ctx context.Context, op Operator, grantID string) (any, error) {
	g, err := s.store.GetGrant(ctx, grantID)
	if err != nil {
		return nil, err
	}
	if g.OperatorID != op.ID {
		return nil, ErrNotGrantee
	}
	if !g.Usable(s.now()) {
		return nil, fmt.Errorf("%w (state: %s)", ErrNotConsented, g.State(s.now()))
	}
	if err := s.store.IncrementGrantUse(ctx, grantID); err != nil {
		return nil, err
	}
	// Audit BEFORE returning data; an unauditable access is no access.
	if err := s.audit.Append(ctx, op.Email, "provider.breakglass_access", grantID, map[string]any{
		"tenant": g.TenantID, "surface": "results.latest", "use": g.UseCount + 1,
	}); err != nil {
		return nil, err
	}
	if s.telemetry == nil {
		return []any{}, nil
	}
	return s.telemetry.LatestResults(g.TenantID), nil
}

func randomToken() (string, error) {
	b, err := crypto.Random(24)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
