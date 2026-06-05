// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package provider

import (
	"net/http"

	"github.com/imfeelingtheagi/probectl/internal/fairness"
)

// The S-T7 fairness surface on the provider plane: cross-tenant accounting
// (who is being shed / throttled and by how much) and the tuneable per-tenant
// policy. ENFORCEMENT is core — it protects the pooled platform in every
// edition; only these operator views/controls ride the provider plane.

// FairnessOps bundles the core fairness capability for the handler. Gate and
// Store are both CORE types (the one-way import rule).
type Fairness struct {
	Gate  *fairness.Gate    // live accounting + cache invalidation
	Store *fairness.PGStore // stored per-tenant policy overrides
}

func (h *Handler) handleFairnessView(w http.ResponseWriter, r *http.Request, _ Operator) error {
	if h.fairness == nil || h.fairness.Gate == nil {
		return ErrNotFound // provider plane without the gate (pool-less tests)
	}
	overrides := map[string]fairness.Policy{}
	if h.fairness.Store != nil {
		if all, err := h.fairness.Store.All(r.Context()); err == nil {
			overrides = all
		}
	}
	snaps := h.fairness.Gate.SnapshotAll()
	return h.writeJSON(w, http.StatusOK, map[string]any{
		"items":     snaps,     // live accounting + effective policy, per seen tenant
		"overrides": overrides, // stored rows (a tenant with an override but no traffic yet)
	})
}

func (h *Handler) handlePutFairness(w http.ResponseWriter, r *http.Request, op Operator) error {
	if h.fairness == nil || h.fairness.Store == nil {
		return ErrNotFound
	}
	if err := h.svc.CheckWritable(); err != nil {
		return err // the read-only license degrade blocks policy writes too
	}
	var in fairness.Policy
	if err := decode(r, &in); err != nil {
		return err
	}
	if in.ResultsPerSec < 0 || in.FlowEventsPerSec < 0 || in.IngestBytesPerSec < 0 ||
		in.BurstSeconds < 0 || in.QueryConcurrency < 0 || in.QueriesPerMin < 0 || in.Weight < 0 {
		return errBadJSON{strErr("fairness bounds must be >= 0 (0 = unlimited / deployment default)")}
	}
	tenantID := r.PathValue("id")
	if err := h.fairness.Store.Upsert(r.Context(), tenantID, in, op.Email); err != nil {
		return err
	}
	if h.fairness.Gate != nil {
		h.fairness.Gate.Invalidate(tenantID) // enforced on the next admission
	}
	if err := h.svc.RecordFairnessChange(r.Context(), op.Email, tenantID, in); err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, in)
}

// fairnessRoutes are appended to Routes() — the S-T7 surface in one file
// (the openapi parity test covers the union).
func fairnessRoutes() []RouteDecl {
	return []RouteDecl{
		{http.MethodGet, "/provider/v1/fairness"},
		{http.MethodPut, "/provider/v1/tenants/{id}/fairness"},
	}
}
