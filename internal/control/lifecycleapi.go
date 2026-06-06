package control

import (
	"context"
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

// WithTenantLife attaches the lifecycle engine. nil = the endpoints answer
// 503 not wired (honesty; community deployments DO get this — it is core —
// but a pool-less unit server has nothing to run it against).
func (s *Server) WithTenantLife(e *tenantlife.Engine) *Server {
	if e != nil {
		s.tenantLife = e
	}
	return s
}

func (s *Server) lifecycleEngine() (*tenantlife.Engine, error) {
	if s.tenantLife == nil {
		return nil, apierror.Unavailable("tenant lifecycle is not wired on this deployment")
	}
	return s.tenantLife, nil
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

// lifecycleStatus is the retention + residency view (the tenant-settings
// card): what the tenant controls (retention) and what it can SEE about
// where its data lives (isolation model, residency — provider-set).
type lifecycleStatus struct {
	tenantlife.RetentionPolicy
	IsolationModel string `json:"isolation_model"`
	Residency      string `json:"residency,omitempty"`
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
	_, isolation, residency, err := s.tenantSlugAndMeta(r.Context(), tid)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, lifecycleStatus{RetentionPolicy: policy, IsolationModel: isolation, Residency: residency})
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
		FlowRetentionDays *int `json:"flow_retention_days"`
	}
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if in.FlowRetentionDays != nil && *in.FlowRetentionDays < 1 {
		return apierror.Validation("flow_retention_days must be >= 1 (null = deployment default)")
	}
	policy := tenantlife.RetentionPolicy{TenantID: tid, FlowRetentionDays: in.FlowRetentionDays, UpdatedBy: "tenant:" + tid}
	if err := e.SetRetention(r.Context(), policy); err != nil {
		return apierror.Internal("retention update failed").Wrap(err)
	}
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		return s.recordAudit(ctx, sc, r, "lifecycle.retention_set", tid, map[string]any{
			"flow_retention_days": in.FlowRetentionDays,
		})
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, policy)
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
