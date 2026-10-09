// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

// The per-tenant lifecycle surface (S-T5, CORE — export + verifiable
// deletion are a compliance right): self-service export, retention/erasure
// controls + residency visibility, and the irreversible full erasure with an
// attestation. All tenant-scoped; the big hammers sit behind the dedicated
// lifecycle.export / lifecycle.erase permissions (admin-seeded).

type tenantLifecycleEngine interface {
	ExportRedacted(context.Context, string, io.Writer, bool) (tenantlife.Manifest, error)
	ExportSubject(context.Context, string, string, io.Writer, bool) (tenantlife.SubjectManifest, error)
	RetentionFor(context.Context, string) (tenantlife.RetentionPolicy, error)
	SetRetention(context.Context, tenantlife.RetentionPolicy, string) error
	Erase(context.Context, string, string, string) (tenantlife.Attestation, error)
	EraseSubject(context.Context, string, string, string, string) (tenantlife.SubjectErasureReport, error)
}

// WithTenantLife attaches the lifecycle engine. nil = the endpoints answer
// 503 not wired (honesty; community deployments DO get this — it is core —
// but a pool-less unit server has nothing to run it against).
func (s *Server) WithTenantLife(e *tenantlife.Engine) *Server {
	if e != nil {
		s.tenantLife = e
	}
	return s
}

func (s *Server) lifecycleEngine() (tenantLifecycleEngine, error) {
	if s.tenantLife == nil {
		return nil, apierror.Unavailable("tenant lifecycle is not wired on this deployment")
	}
	return s.tenantLife, nil
}

// tenantSlugAndMeta reads the caller's registry row (tenants has no RLS — it
// is the provider-scoped registry, read as the provider role; this read is
// keyed by the PRINCIPAL'S own tenant id, never caller input).
func (s *Server) tenantSlugAndMeta(ctx context.Context, tenantID string) (slug, isolation, residency string, err error) {
	if s.pool == nil {
		return "", "pooled", "", nil
	}
	err = tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		return q.QueryRow(ctx,
			`SELECT slug, isolation_model, residency FROM tenants WHERE id = $1`, tenantID).
			Scan(&slug, &isolation, &residency)
	})
	if err != nil {
		return "", "", "", apierror.Internal("tenant registry read failed").Wrap(err)
	}
	return slug, isolation, residency, nil
}

// handleLifecycleExport streams the tenant's portability bundle (tar.gz).
func (s *Server) handleLifecycleExport(w http.ResponseWriter, r *http.Request) error {
	// WEB-04: lift the global WriteTimeout for this long-running response.
	extendWriteDeadline(w, exportWriteBudget)
	e, err := s.lifecycleEngine()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="probectl-tenant-export.tar.gz"`)
	// S-EE3: ?redact=true masks PII-class values per the tenant's governance
	// policy (and the policy itself can force redaction).
	redact := r.URL.Query().Get("redact") == "true"
	if _, err := e.ExportRedacted(r.Context(), tid, w, redact); err != nil {
		// Headers are committed; the truncated stream is the failure signal.
		s.log.Error("tenant export failed", "tenant_id", tid, "error", err.Error())
		return nil
	}
	return nil
}

type lifecycleSubjectExportRequest struct {
	Subject string `json:"subject"`
	Redact  bool   `json:"redact"`
}

// handleLifecycleSubjectExport streams a subject-scoped portability bundle. It
// is POST, not GET, so the subject identifier does not land in URLs.
func (s *Server) handleLifecycleSubjectExport(w http.ResponseWriter, r *http.Request) error {
	// WEB-04: lift the global WriteTimeout for this long-running response.
	extendWriteDeadline(w, exportWriteBudget)
	e, err := s.lifecycleEngine()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var in lifecycleSubjectExportRequest
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if strings.TrimSpace(in.Subject) == "" {
		return apierror.Validation("subject is required")
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="probectl-subject-export.tar.gz"`)
	if _, err := e.ExportSubject(r.Context(), tid, in.Subject, w, in.Redact); err != nil {
		s.log.Error("subject export failed", "tenant_id", tid, "error", err.Error())
		return nil
	}
	return nil
}

// lifecycleStatus is the retention + residency view (the tenant-settings
// card): what the tenant controls (retention) and what it can SEE about
// where its data lives (isolation model, residency — provider-set).
type lifecycleStatus struct {
	tenantlife.RetentionPolicy
	IsolationModel string `json:"isolation_model"`
	Residency      string `json:"residency,omitempty"`
}

func (s *Server) lifecycleStatusForPolicy(ctx context.Context, tenantID string, policy tenantlife.RetentionPolicy) (lifecycleStatus, error) {
	_, isolation, residency, err := s.tenantSlugAndMeta(ctx, tenantID)
	if err != nil {
		return lifecycleStatus{}, err
	}
	return lifecycleStatus{RetentionPolicy: policy, IsolationModel: isolation, Residency: residency}, nil
}

func (s *Server) handleLifecycleRetentionGet(w http.ResponseWriter, r *http.Request) error {
	e, err := s.lifecycleEngine()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	policy, err := e.RetentionFor(r.Context(), tid)
	if err != nil {
		return apierror.Internal("retention read failed").Wrap(err)
	}
	status, err := s.lifecycleStatusForPolicy(r.Context(), tid, policy)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, status)
	return nil
}

func (s *Server) handleLifecycleRetentionPut(w http.ResponseWriter, r *http.Request) error {
	e, err := s.lifecycleEngine()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var in struct {
		FlowRetentionDays            *int `json:"flow_retention_days"`
		OtelRetentionDays            *int `json:"otel_retention_days"`
		EBPFRetentionDays            *int `json:"ebpf_retention_days"`
		PathRetentionDays            *int `json:"path_retention_days"`
		AuditRetentionDays           *int `json:"audit_retention_days"`
		AIAnswerRetentionDays        *int `json:"ai_answer_retention_days"`
		ObjectRetentionDays          *int `json:"object_retention_days"`
		DerivedIdentityRetentionDays *int `json:"derived_identity_retention_days"`
	}
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	// AUTHZ-18: the production deployment profiles (multi-tenant, regulated)
	// carry a compliance obligation to keep the tenant audit trail. Reject an
	// audit_retention_days below the profile-mandated floor — a well-formed but
	// non-compliant value, hence 422 — so the trail cannot be shrunk below it
	// even when the operator left PROBECTL_AUDIT_RETENTION_MIN unset (0 disables
	// the explicit AUD-07 floor, but the profile minimum still holds).
	// docs/guardrails.md G7-N (tamper-evident audit trail).
	if in.AuditRetentionDays != nil && s.cfg != nil {
		if profileFloor := profileAuditRetentionFloorDays(s.cfg.DeploymentProfile); profileFloor > 0 && *in.AuditRetentionDays < profileFloor {
			return apierror.Validation(fmt.Sprintf(
				"audit_retention_days cannot be below the %s deployment profile minimum of %d days",
				s.cfg.DeploymentProfile, profileFloor))
		}
	}
	// AUD-07: a tenant admin cannot shrink audit retention below the deployment
	// compliance floor (PROBECTL_AUDIT_RETENTION_MIN).
	if in.AuditRetentionDays != nil && s.cfg != nil && s.cfg.AuditRetentionMin > 0 {
		floorDays := int((s.cfg.AuditRetentionMin + 24*time.Hour - 1) / (24 * time.Hour))
		if *in.AuditRetentionDays < floorDays {
			return apierror.BadRequest(fmt.Sprintf("audit_retention_days cannot be below the deployment floor of %d days", floorDays))
		}
	}
	// WEB-08: this is a partial update — a field omitted (JSON null / absent)
	// means "leave it unchanged", not "reset to the deployment default". Merge
	// the submitted fields over the tenant's current policy so saving one knob
	// never silently clears the others.
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(tid))
	current, err := e.RetentionFor(ctx, tid)
	if err != nil {
		return apierror.Internal("retention read failed").Wrap(err)
	}
	keep := func(set, cur *int) *int {
		if set != nil {
			return set
		}
		return cur
	}
	policy := tenantlife.RetentionPolicy{
		TenantID:                     tid,
		FlowRetentionDays:            keep(in.FlowRetentionDays, current.FlowRetentionDays),
		OtelRetentionDays:            keep(in.OtelRetentionDays, current.OtelRetentionDays),
		EBPFRetentionDays:            keep(in.EBPFRetentionDays, current.EBPFRetentionDays),
		PathRetentionDays:            keep(in.PathRetentionDays, current.PathRetentionDays),
		AuditRetentionDays:           keep(in.AuditRetentionDays, current.AuditRetentionDays),
		AIAnswerRetentionDays:        keep(in.AIAnswerRetentionDays, current.AIAnswerRetentionDays),
		ObjectRetentionDays:          keep(in.ObjectRetentionDays, current.ObjectRetentionDays),
		DerivedIdentityRetentionDays: keep(in.DerivedIdentityRetentionDays, current.DerivedIdentityRetentionDays),
		UpdatedBy:                    auditActor(r), // DPR-083: the principal who set the clocks, not the tenant id
	}
	if err := validateLifecycleRetentionPolicy(policy); err != nil {
		return err
	}
	if err := e.SetRetention(ctx, policy, auditActor(r)); err != nil {
		if errors.Is(err, tenantlife.ErrAuditRetentionExceedsMaximum) {
			return apierror.Validation("audit_retention_days cannot exceed the deployment audit-retention maximum")
		}
		return apierror.Internal("retention update failed").Wrap(err)
	}
	status, err := s.lifecycleStatusForPolicy(r.Context(), tid, policy)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, status)
	return nil
}

// profileAuditRetentionFloorDays returns the mandatory audit-retention floor
// (in days) that a deployment profile imposes on a tenant override, regardless
// of the operator-set PROBECTL_AUDIT_RETENTION_MIN (AUTHZ-18). The multi-tenant
// and regulated profiles carry a compliance obligation to retain the audit
// trail; this mirrors the config loader's audit-retention-minimum default so
// the floor holds even when the explicit knob is left unset. 0 = the profile
// imposes no intrinsic floor (single / unset / dev).
func profileAuditRetentionFloorDays(profile string) int {
	switch profile {
	case "multi-tenant", "regulated":
		return 30
	default:
		return 0
	}
}

func validateLifecycleRetentionPolicy(p tenantlife.RetentionPolicy) error {
	fields := map[string]*int{
		"flow_retention_days":             p.FlowRetentionDays,
		"otel_retention_days":             p.OtelRetentionDays,
		"ebpf_retention_days":             p.EBPFRetentionDays,
		"path_retention_days":             p.PathRetentionDays,
		"audit_retention_days":            p.AuditRetentionDays,
		"ai_answer_retention_days":        p.AIAnswerRetentionDays,
		"object_retention_days":           p.ObjectRetentionDays,
		"derived_identity_retention_days": p.DerivedIdentityRetentionDays,
	}
	for name, days := range fields {
		if days != nil && *days < 1 {
			return apierror.Validation(name + " must be >= 1 (null = deployment default)")
		}
	}
	return nil
}

// handleLifecycleErase runs the IRREVERSIBLE verifiable erasure. The caller
// must confirm with the tenant's exact slug — a fat-fingered call cannot
// erase a deployment.
func (s *Server) handleLifecycleErase(w http.ResponseWriter, r *http.Request) error {
	e, err := s.lifecycleEngine()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var in struct {
		Confirm string `json:"confirm"`
	}
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	slug, _, _, err := s.tenantSlugAndMeta(r.Context(), tid)
	if err != nil {
		return err
	}
	if slug == "" || !strings.EqualFold(strings.TrimSpace(in.Confirm), slug) {
		return apierror.Validation("confirm must equal the tenant slug exactly — erasure is irreversible")
	}
	// AUTHZ-18: attribute the irreversible erase — its attestation and every
	// provider audit event (lifecycle.erase_fence, lifecycle.erase) — to the
	// authenticated human operator who initiated it, never a synthetic
	// "tenant:<id>" actor. A destructive lifecycle action must name the person
	// accountable for it. docs/guardrails.md G7-N (tamper-evident audit trail).
	att, err := e.Erase(r.Context(), tid, slug, auditActor(r))
	if err != nil {
		return apierror.Internal("erasure failed").Wrap(err)
	}
	writeJSON(w, http.StatusOK, att)
	return nil
}

type lifecycleSubjectEraseRequest struct {
	Subject string `json:"subject"`
	Confirm string `json:"confirm"`
	Reason  string `json:"reason"`
}

func (s *Server) handleLifecycleSubjectErase(w http.ResponseWriter, r *http.Request) error {
	e, err := s.lifecycleEngine()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var in lifecycleSubjectEraseRequest
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	subject := strings.TrimSpace(in.Subject)
	if subject == "" {
		return apierror.Validation("subject is required")
	}
	if strings.TrimSpace(in.Confirm) != subject {
		return apierror.Validation("confirm must equal subject exactly — subject erasure is irreversible")
	}
	report, err := e.EraseSubject(r.Context(), tid, subject, auditActor(r), in.Reason)
	if err != nil {
		return apierror.Internal("subject erasure failed").Wrap(err)
	}
	writeJSON(w, http.StatusOK, report)
	return nil
}
