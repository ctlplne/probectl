// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// See ee/doc.go for the boundary rules every ee/ file observes.

package provider

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	coreaudit "github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// AuditSink receives provider-plane audit events. The production sink wraps
// audit.ProviderAppend (the separate, equally tamper-evident provider stream —
// CLAUDE.md §7 guardrail 7); tests capture events in memory.
type AuditSink interface {
	Append(ctx context.Context, actor, action, target string, data map[string]any) error
	AppendBreakGlass(
		ctx context.Context,
		actor, action, target string,
		data map[string]any,
		attribution coreaudit.IRAttribution,
	) error
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
	// ErrGrantDecided is returned when a consent/deny/revoke loses a race to
	// another decision on the same grant. The storage-layer predicates refuse
	// the second writer rather than letting it clobber the first (S-ae06d833).
	ErrGrantDecided = errors.New("provider: break-glass grant was already decided by a concurrent request")
	ErrForbidden    = errors.New("provider: forbidden")
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

	// log + lockoutAuditFailures make the best-effort lockout-audit append
	// OBSERVABLE (CODE-008): a dropped append was previously discarded with
	// `_ =`, so a silently failing provider audit stream looked healthy.
	log                  *slog.Logger
	lockoutAuditFailures atomic.Uint64

	// S-T2: nil = pooled-only (the siloed_isolation feature is not licensed).
	silo SiloOps
	// routerInvalidate drops the isolation router's registry cache after a
	// lifecycle change, so new/changed tenants route correctly at once.
	routerInvalidate func()
	// seedRoles publishes the tenant's system roles at activation (DPR-035);
	// nil in unit tests that never activate a tenant.
	seedRoles func(ctx context.Context, tenantID string) error
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
		envelope: env, now: time.Now, maxGrantTTL: maxGrantTTL, log: slog.Default(),
	}, nil
}

// withClock overrides time (tests).
func (s *Service) withClock(now func() time.Time) *Service {
	s.now = now
	return s
}

// WithSilo attaches the S-T2 isolation capability (the attach seam passes it
// only when the license grants siloed_isolation) and the router-cache
// invalidation hook.
// WithRoleSeeder installs the function that seeds admin/editor/viewer inside a
// newly published tenant. Without it a provisioned tenant has no role to bind
// and cannot be administered (DPR-035).
func (s *Service) WithRoleSeeder(fn func(ctx context.Context, tenantID string) error) *Service {
	s.seedRoles = fn
	return s
}

func (s *Service) WithSilo(ops SiloOps, invalidate func()) *Service {
	s.silo = ops
	s.routerInvalidate = invalidate
	return s
}

// CheckWritable exposes the read-only-degrade gate for surfaces (S-T3 quota
// writes) that live outside this file.
func (s *Service) CheckWritable() error { return s.writable() }

// RecordGovernanceChange audits a data-governance policy update.
func (s *Service) RecordGovernanceChange(ctx context.Context, actor, tenantID, redactFrom string, redactExport bool, overrides int) error {
	return s.audit.Append(ctx, actor, "provider.governance_set", tenantID, map[string]any{
		"redact_from": redactFrom, "redact_export": redactExport, "classification_overrides": overrides,
	})
}

// RecordFairnessChange audits a fairness-policy update on the provider stream.
func (s *Service) RecordFairnessChange(ctx context.Context, actor, tenantID string, p fairness.Policy) error {
	return s.audit.Append(ctx, actor, "provider.fairness_set", tenantID, map[string]any{
		"results_per_sec":        p.ResultsPerSec,
		"flow_events_per_sec":    p.FlowEventsPerSec,
		"ingest_bytes_per_sec":   p.IngestBytesPerSec,
		"device_metrics_per_sec": p.DeviceMetricsPerSec,
		"otlp_series_per_sec":    p.OTLPSeriesPerSec,
		"burst_seconds":          p.BurstSeconds,
		"query_concurrency":      p.QueryConcurrency,
		"queries_per_min":        p.QueriesPerMin,
		"weight":                 p.Weight,
	})
}

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

// RecordTenantErase audits a provider-triggered erasure on the provider stream.
func (s *Service) RecordTenantErase(ctx context.Context, actor, tenantID string, complete bool, reportSHA string) error {
	return s.audit.Append(ctx, actor, "provider.tenant_erase", tenantID, map[string]any{
		"complete": complete, "report_sha256": reportSHA,
	})
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
		return Operator{}, "", validationError(fmt.Sprintf("provider: role must be %q or %q", RoleAdmin, RoleOperator))
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !strings.Contains(email, "@") {
		return Operator{}, "", validationError("provider: a valid operator email is required")
	}
	token, err := randomToken()
	if err != nil {
		return Operator{}, "", err
	}
	var op Operator
	err = s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
		var err error
		op, err = store.CreateOperator(ctx,
			Operator{Email: email, Name: name, Role: role, Status: "disabled"},
			crypto.Hash([]byte(token)),
		)
		if err != nil {
			return err
		}
		return audit.Append(ctx, actor, "provider.operator_create", op.ID, map[string]any{"email": email, "role": role})
	})
	if err != nil {
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
	token, err := randomToken()
	if err != nil {
		return Operator{}, "", err
	}
	var op Operator
	err = s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
		var err error
		op, err = store.BootstrapOperator(ctx,
			Operator{Email: strings.ToLower(email), Name: name, Role: RoleAdmin, Status: "disabled"},
			crypto.Hash([]byte(token)),
		)
		if err != nil {
			return err
		}
		return audit.Append(ctx, "bootstrap", "provider.bootstrap", op.ID, map[string]any{"email": op.Email})
	})
	if err != nil {
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
	if err := s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
		if err := store.SetOperatorTOTP(ctx, op.ID, sealed); err != nil {
			return err
		}
		// The event proves the credential binding changed without recording the
		// one-time TOTP secret or any sealed-key material.
		return audit.Append(ctx, op.Email, "provider.operator_totp_bound", op.ID, nil)
	}); err != nil {
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
		return Operator{}, validationError("provider: operator passwords must be at least 12 characters")
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
	if err := s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
		if err := store.ActivateOperator(ctx, op.ID, hash); err != nil {
			return err
		}
		return audit.Append(ctx, op.Email, "provider.operator_enrolled", op.ID, nil)
	}); err != nil {
		return Operator{}, err
	}
	op.Enrolled, op.Status = true, "active"
	return *op, nil
}

// Login verifies email + password + TOTP (MFA is mandatory in the provider
// domain — there is no password-only path). Failures are uniform: no signal
// distinguishes a wrong password from a wrong code or an unknown email.
// RecordLoginLockout lands an operator-login lockout in the SEPARATE,
// tamper-evident provider audit stream (SEC-003 / guardrail 7). Best-effort:
// an audit-sink failure must not mask the lockout itself (already enforced).
func (s *Service) RecordLoginLockout(ctx context.Context, key string, failures int, lockout time.Duration) {
	// Best-effort: the lockout is already enforced, so an audit-sink failure
	// must not block it — but it must not be SILENT either (CODE-008). Log +
	// count the failure so a broken provider audit stream is visible.
	if err := s.audit.Append(ctx, "system", "provider.auth_lockout", "", map[string]any{
		"key": key, "failures": failures, "lockout": lockout.String(),
	}); err != nil {
		s.lockoutAuditFailures.Add(1)
		s.log.Error("provider audit append failed for auth lockout (lockout still enforced; audit trail incomplete)",
			"key", key, "failures", failures, "error", err.Error(),
			"audit_failures_total", s.lockoutAuditFailures.Load())
	}
}

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
		return validationError("provider: status must be active or disabled")
	}
	return s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
		if err := store.SetOperatorStatus(ctx, id, status); err != nil {
			return err
		}
		return audit.Append(ctx, actor, "provider.operator_status", id, map[string]any{"status": status})
	})
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
		return Tenant{}, validationError("provider: slug must be lowercase alphanumeric/hyphen, 2-63 chars")
	}
	if isolationModel == "" {
		isolationModel = string(tenancy.IsolationPooled)
	}
	if !tenancy.ValidIsolationModel(isolationModel) {
		return Tenant{}, validationError("provider: isolation_model must be pooled, siloed, or hybrid")
	}
	model := tenancy.IsolationModel(isolationModel)
	if model != tenancy.IsolationPooled {
		if s.silo == nil {
			return Tenant{}, fmt.Errorf("%w: siloed/hybrid isolation requires the siloed_isolation license feature", ErrForbidden)
		}
		if !s.silo.ValidResidency(residency) {
			return Tenant{}, validationError(fmt.Sprintf("provider: unknown residency %q (configured: %s)", residency, strings.Join(s.silo.Planes(), ", ")))
		}
	} else if residency != "" {
		return Tenant{}, validationError("provider: residency targeting requires a siloed or hybrid tenant")
	}
	tenantBand := s.lic.TenantBand()
	if tenantBand > 0 {
		n, err := s.store.CountActiveTenants(ctx)
		if err != nil {
			return Tenant{}, err
		}
		if n >= tenantBand {
			return Tenant{}, fmt.Errorf("%w: %d of %d in use", ErrBandExhausted, n, tenantBand)
		}
	}
	name = strings.TrimSpace(name)
	if model == tenancy.IsolationPooled {
		var t Tenant
		err := s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
			var err error
			t, err = store.CreateTenant(ctx, slug, name, isolationModel, residency, tenantBand)
			if err != nil {
				return err
			}
			return audit.Append(ctx, actor, "provider.tenant_provision", t.ID, tenantProvisionAuditData(t))
		})
		if err != nil {
			return Tenant{}, err
		}
		s.invalidateRouter()
		if err := s.seedSystemRoles(ctx, t); err != nil {
			return Tenant{}, err
		}
		return t, nil
	}

	// Isolated provisioning crosses transactional stores. Stage the final
	// tenant identity outside the routable registry, then publish it only after
	// every idempotent silo leg has succeeded. A retry with the same slug and
	// configuration reuses this UUID.
	var t Tenant
	existing, err := s.store.TenantBySlug(ctx, slug)
	switch {
	case err == nil:
		if !sameTenantProvision(*existing, name, isolationModel, residency) {
			return Tenant{}, fmt.Errorf("%w: slug is already active or belongs to a different provisioning request", ErrConflict)
		}
		t = *existing
		if err := s.recordTenantProvisionEvent(ctx, actor, "provider.tenant_provision_attempt", t, nil); err != nil {
			return Tenant{}, err
		}
	case errors.Is(err, ErrNotFound):
		err = s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
			var err error
			t, err = store.CreateTenantProvision(ctx, slug, name, isolationModel, residency)
			if err != nil {
				return err
			}
			return audit.Append(ctx, actor, "provider.tenant_provision_attempt", t.ID, tenantProvisionAuditData(t))
		})
		if errors.Is(err, ErrConflict) {
			// A concurrent first attempt may have created the staging row after
			// our lookup. Resume that exact request instead of making the caller
			// discover and retry an avoidable 409.
			existing, lookupErr := s.store.TenantBySlug(ctx, slug)
			if lookupErr != nil {
				return Tenant{}, err
			}
			if !sameTenantProvision(*existing, name, isolationModel, residency) {
				return Tenant{}, err
			}
			t = *existing
			if err := s.recordTenantProvisionEvent(ctx, actor, "provider.tenant_provision_attempt", t, nil); err != nil {
				return Tenant{}, err
			}
		} else if err != nil {
			return Tenant{}, err
		}
	default:
		return Tenant{}, err
	}

	if err := s.silo.Provision(ctx, t.ID, residency, model); err != nil {
		// Record how far the attempt got BEFORE returning, so a stranded row
		// carries evidence an operator can act on rather than a bare
		// "provisioning" status (S-fadcec95). The provisioner itself has
		// already compensated its completed ClickHouse legs.
		ledgerCtx, ledgerCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer ledgerCancel()
		if lerr := s.store.WithAuditedMutation(ledgerCtx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
			if err := store.RecordProvisionAttempt(ctx, t.ID, "silo", err.Error()); err != nil {
				return err
			}
			return audit.Append(ctx, actor, "provider.tenant_provision_stranded", t.ID,
				map[string]any{"last_step": "silo"})
		}); lerr != nil {
			s.log.Warn("provisioning step ledger unavailable",
				"tenant_id", t.ID, "error", lerr.Error())
		}
		auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		auditErr := s.recordTenantProvisionEvent(auditCtx, actor, "provider.tenant_provision_failure", t, map[string]any{
			"error_category": tenantProvisionFailureCategory(tenantProvisionSiloPhase, err),
		})
		provisionErr := fmt.Errorf("silo provisioning failed (re-run provision to complete): %w", err)
		if auditErr != nil {
			return Tenant{}, errors.Join(provisionErr, fmt.Errorf("record provisioning failure: %w", auditErr))
		}
		return Tenant{}, provisionErr
	}

	published := false
	err = s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
		completed, didPublish, err := store.CompleteTenantProvision(ctx, t.ID, tenantBand)
		if err != nil {
			return err
		}
		t, published = completed, didPublish
		if !published {
			return nil
		}
		return audit.Append(ctx, actor, "provider.tenant_provision", t.ID, tenantProvisionAuditData(t))
	})
	if err != nil {
		auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		auditErr := s.recordTenantProvisionEvent(auditCtx, actor, "provider.tenant_provision_failure", t, map[string]any{
			"error_category": tenantProvisionFailureCategory(tenantProvisionRegistryPhase, err),
		})
		if auditErr != nil {
			return Tenant{}, errors.Join(err, fmt.Errorf("record provisioning failure: %w", auditErr))
		}
		return Tenant{}, err
	}
	if published {
		s.invalidateRouter()
		if err := s.seedSystemRoles(ctx, t); err != nil {
			return Tenant{}, err
		}
	}
	return t, nil
}

func tenantProvisionAuditData(t Tenant) map[string]any {
	return map[string]any{
		"slug": t.Slug, "name": t.Name,
		"isolation_model": t.IsolationModel, "residency": t.Residency,
	}
}

func sameTenantProvision(t Tenant, name, isolationModel, residency string) bool {
	return t.Status == "provisioning" &&
		t.Name == name &&
		t.IsolationModel == isolationModel &&
		t.Residency == residency
}

type tenantProvisionFailurePhase uint8

const (
	tenantProvisionSiloPhase tenantProvisionFailurePhase = iota + 1
	tenantProvisionRegistryPhase
)

func tenantProvisionFailureCategory(phase tenantProvisionFailurePhase, err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case phase == tenantProvisionRegistryPhase && errors.Is(err, ErrBandExhausted):
		return "tenant_band_exhausted"
	case phase == tenantProvisionSiloPhase:
		return "silo_provision_failed"
	case phase == tenantProvisionRegistryPhase:
		return "registry_publish_failed"
	default:
		return "provision_failed"
	}
}

func (s *Service) recordTenantProvisionEvent(
	ctx context.Context,
	actor, action string,
	t Tenant,
	extra map[string]any,
) error {
	data := tenantProvisionAuditData(t)
	for key, value := range extra {
		data[key] = value
	}
	return s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, _ MutationStore, audit AuditSink) error {
		return audit.Append(ctx, actor, action, t.ID, data)
	})
}

// Configure renames a tenant.
func (s *Service) Configure(ctx context.Context, actor, id, name string) (Tenant, error) {
	if err := s.writable(); err != nil {
		return Tenant{}, err
	}
	var t Tenant
	err := s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
		var err error
		t, err = store.RenameTenant(ctx, id, strings.TrimSpace(name))
		if err != nil {
			return err
		}
		return audit.Append(ctx, actor, "provider.tenant_configure", id, map[string]any{"name": name})
	})
	if err != nil {
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
// the licensed band. It is deliberately non-destructive for every isolation
// model. The separate, slug-confirmed Erase flow must verify and delete
// tenant data, crypto-shred the IR attribution key, and retain the encrypted
// signed sidecar. Dropping a silo here would either bypass that plan or erase
// its retained evidence. Physical container reclamation therefore remains a
// separate, tombstone-aware maintenance operation.
func (s *Service) Offboard(ctx context.Context, actor, id string) (Tenant, error) {
	return s.setStatus(ctx, actor, id, "offboarding", "provider.tenant_offboard")
}

func (s *Service) setStatus(ctx context.Context, actor, id, status, action string) (Tenant, error) {
	if err := s.writable(); err != nil {
		return Tenant{}, err
	}
	var t Tenant
	err := s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
		var err error
		t, err = store.SetTenantStatus(ctx, id, status)
		if err != nil {
			return err
		}
		return audit.Append(ctx, actor, action, id, map[string]any{"slug": t.Slug})
	})
	if err != nil {
		return Tenant{}, err
	}
	s.invalidateRouter()
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
		return Grant{}, validationError("provider: break-glass requires a reason")
	}
	if ttl <= 0 || ttl > s.maxGrantTTL {
		return Grant{}, validationError(fmt.Sprintf("provider: ttl must be within (0, %s]", s.maxGrantTTL))
	}
	now := s.now()
	var g Grant
	err := s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
		var err error
		g, err = store.CreateGrant(ctx, Grant{
			OperatorID: op.ID, OperatorEmail: op.Email, TenantID: tenantID,
			Reason: reason, Scope: "read", GrantedBy: op.Email,
			GrantedAt: now, ExpiresAt: now.Add(ttl),
		})
		if err != nil {
			return err
		}
		data := map[string]any{
			"tenant": tenantID, "reason": reason,
			"expires_at": g.ExpiresAt.UTC().Format(time.RFC3339),
		}
		return audit.AppendBreakGlass(
			ctx,
			op.Email,
			"provider.breakglass_request",
			g.ID,
			data,
			coreaudit.IRAttribution{
				Operator: op.ID,
				TenantID: tenantID,
				Grant:    g.ID,
				Surface:  "provider.breakglass.request",
				Consent:  GrantPending,
				Outcome:  "requested",
				Reason:   reason,
			},
		)
	})
	if err != nil {
		return Grant{}, err
	}
	return g, nil
}

// ListStrandedProvisions surfaces in-flight provisioning attempts older than
// age so the provider console can show what happened and offer retry or
// abandon. age <= 0 lists every in-flight attempt.
func (s *Service) ListStrandedProvisions(ctx context.Context, age time.Duration) ([]StrandedProvision, error) {
	return s.store.ListStrandedProvisions(ctx, age)
}

// AbandonProvision drops a stranded attempt's staging row after tearing down
// whatever external state it created. Teardown runs FIRST: abandoning the row
// while a silo database survives is exactly the orphan this finding is about.
func (s *Service) AbandonProvision(ctx context.Context, actor, id string) error {
	stranded, err := s.store.ListStrandedProvisions(ctx, 0)
	if err != nil {
		return err
	}
	var target *StrandedProvision
	for i := range stranded {
		if stranded[i].ID == id {
			target = &stranded[i]
			break
		}
	}
	if target == nil {
		return ErrNotFound
	}
	if s.silo != nil {
		if err := s.silo.Teardown(ctx, target.ID, target.Residency,
			tenancy.IsolationModel(target.IsolationModel)); err != nil {
			return fmt.Errorf("provider: tear down the stranded silo before abandoning it: %w", err)
		}
	}
	return s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
		removed, err := store.AbandonProvision(ctx, id)
		if err != nil {
			return err
		}
		if !removed {
			return ErrNotFound
		}
		return audit.Append(ctx, actor, "provider.tenant_provision_abandoned", id, map[string]any{
			"slug": target.Slug, "last_step": target.LastStep,
		})
	})
}

// ReapStrandedProvisions abandons every attempt older than age, bounded by
// limit per run so a sweep can never become an unbounded destructive loop. It
// returns how many it removed; each removal is separately audited.
func (s *Service) ReapStrandedProvisions(ctx context.Context, actor string, age time.Duration, limit int) (int, error) {
	if age <= 0 {
		return 0, fmt.Errorf("provider: refusing to reap with a non-positive age (that would abandon in-flight provisioning)")
	}
	if limit <= 0 {
		limit = 50
	}
	stranded, err := s.store.ListStrandedProvisions(ctx, age)
	if err != nil {
		return 0, err
	}
	reaped := 0
	var errs []error
	for _, p := range stranded {
		if reaped >= limit {
			break
		}
		if err := s.AbandonProvision(ctx, actor, p.ID); err != nil {
			errs = append(errs, fmt.Errorf("reap %s: %w", p.Slug, err))
			continue
		}
		reaped++
	}
	return reaped, errors.Join(errs...)
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
		return Grant{}, validationError(fmt.Sprintf("provider: grant is %s, not pending", g.State(s.now())))
	}
	var out *Grant
	action := "provider.breakglass_consent"
	err = s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
		var err error
		if approve {
			out, err = store.ConsentGrant(ctx, grantID, by, s.now())
		} else {
			action = "provider.breakglass_deny"
			out, err = store.DenyGrant(ctx, grantID, by, s.now())
		}
		if err != nil {
			return err
		}
		consent := "tenant-denied:" + by
		outcome := GrantDenied
		if approve {
			consent = "tenant-approved:" + by
			outcome = "approved"
		}
		return audit.AppendBreakGlass(
			ctx,
			by,
			action,
			grantID,
			map[string]any{"tenant": tenantID, "reason": out.Reason},
			coreaudit.IRAttribution{
				Operator: out.OperatorID,
				TenantID: tenantID,
				Grant:    grantID,
				Surface:  "provider.breakglass.consent",
				Consent:  consent,
				Outcome:  outcome,
				Reason:   out.Reason,
			},
		)
	})
	if err != nil {
		return Grant{}, err
	}
	return *out, nil
}

// Revoke ends a grant early (operator-side; also reachable to admins).
func (s *Service) Revoke(ctx context.Context, actor, grantID string) (Grant, error) {
	var g *Grant
	err := s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
		var err error
		g, err = store.RevokeGrant(ctx, grantID, actor, s.now())
		if err != nil {
			return err
		}
		return audit.AppendBreakGlass(
			ctx,
			actor,
			"provider.breakglass_revoke",
			grantID,
			map[string]any{"tenant": g.TenantID, "reason": g.Reason},
			coreaudit.IRAttribution{
				Operator: g.OperatorID,
				TenantID: g.TenantID,
				Grant:    grantID,
				Surface:  "provider.breakglass.revoke",
				Consent:  "revoked-by:" + actor,
				Outcome:  GrantRevoked,
				Reason:   g.Reason,
			},
		)
	})
	if err != nil {
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
	var g *Grant
	// The authoritative grantee/consent/revoke/expiry check, use increment, and
	// audit append share one transaction. A revoke racing this path therefore
	// wins before access or follows a fully recorded access; stale snapshots
	// cannot authorize tenant telemetry.
	if err := s.store.WithAuditedMutation(ctx, s.audit, func(ctx context.Context, store MutationStore, audit AuditSink) error {
		var err error
		g, err = store.UseGrant(ctx, grantID, op.ID, s.now())
		if err != nil {
			return err
		}
		return audit.AppendBreakGlass(
			ctx,
			op.Email,
			"provider.breakglass_access",
			grantID,
			map[string]any{
				"tenant": g.TenantID, "surface": "results.latest",
				"use": g.UseCount, "reason": g.Reason,
			},
			coreaudit.IRAttribution{
				Operator: g.OperatorID,
				TenantID: g.TenantID,
				Grant:    grantID,
				Surface:  "results.latest",
				Consent:  "tenant-approved:" + g.ConsentedBy,
				Outcome:  "accessed",
				Reason:   g.Reason,
			},
		)
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

// seedSystemRoles runs the installed role seeder for a tenant that just became
// active. Failing here is loud on purpose: an active tenant nobody can be
// granted access to is worse than a provisioning error the operator can retry
// (bootstrap-admin also self-heals a tenant without system roles).
func (s *Service) seedSystemRoles(ctx context.Context, t Tenant) error {
	if s.seedRoles == nil {
		return nil
	}
	if err := s.seedRoles(ctx, t.ID); err != nil {
		return fmt.Errorf("provider: tenant %s published but its system roles could not be seeded: %w", t.ID, err)
	}
	return nil
}
