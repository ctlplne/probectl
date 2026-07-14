// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantlife"
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
	SetRetention(context.Context, tenantlife.RetentionPolicy) error
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

var recordLifecycleRetentionAudit = func(s *Server, r *http.Request, tid string, p tenantlife.RetentionPolicy) error {
	return s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		return s.recordAudit(ctx, sc, r, "lifecycle.retention_set", tid, map[string]any{
			"flow_retention_days":             p.FlowRetentionDays,
			"otel_retention_days":             p.OtelRetentionDays,
			"ebpf_retention_days":             p.EBPFRetentionDays,
			"path_retention_days":             p.PathRetentionDays,
			"audit_retention_days":            p.AuditRetentionDays,
			"ai_answer_retention_days":        p.AIAnswerRetentionDays,
			"object_retention_days":           p.ObjectRetentionDays,
			"derived_identity_retention_days": p.DerivedIdentityRetentionDays,
		})
	})
}

// tenantSlugAndMeta reads the caller's registry row (tenants has no RLS — it
// is the provider-scoped registry; this read is keyed by the PRINCIPAL'S own
// tenant id, never caller input).
func (s *Server) tenantSlugAndMeta(ctx context.Context, tenantID string) (slug, isolation, residency string, err error) {
	if s.pool == nil {
		return "", "pooled", "", nil
	}
	err = s.pool.QueryRow(ctx,
		`SELECT slug, isolation_model, residency FROM tenants WHERE id = $1`, tenantID).
		Scan(&slug, &isolation, &residency)
	if err != nil {
		return "", "", "", apierror.Internal("tenant registry read failed").Wrap(err)
	}
	return slug, isolation, residency, nil
}

// handleLifecycleExport streams the tenant's portability bundle (tar.gz).
func (s *Server) handleLifecycleExport(w http.ResponseWriter, r *http.Request) error {
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
	policy := tenantlife.RetentionPolicy{
		TenantID:                     tid,
		FlowRetentionDays:            in.FlowRetentionDays,
		OtelRetentionDays:            in.OtelRetentionDays,
		EBPFRetentionDays:            in.EBPFRetentionDays,
		PathRetentionDays:            in.PathRetentionDays,
		AuditRetentionDays:           in.AuditRetentionDays,
		AIAnswerRetentionDays:        in.AIAnswerRetentionDays,
		ObjectRetentionDays:          in.ObjectRetentionDays,
		DerivedIdentityRetentionDays: in.DerivedIdentityRetentionDays,
		UpdatedBy:                    "tenant:" + tid,
	}
	if err := validateLifecycleRetentionPolicy(policy); err != nil {
		return err
	}
	if err := e.SetRetention(r.Context(), policy); err != nil {
		return apierror.Internal("retention update failed").Wrap(err)
	}
	if err := recordLifecycleRetentionAudit(s, r, tid, policy); err != nil {
		return err
	}
	status, err := s.lifecycleStatusForPolicy(r.Context(), tid, policy)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, status)
	return nil
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
	att, err := e.Erase(r.Context(), tid, slug, "tenant:"+tid)
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
