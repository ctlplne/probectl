// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/tenantlife"
)

// Write-deadline budgets for the provider plane's long-running responses
// (WEB-04). The control server's absolute WriteTimeout (default 15s) would
// otherwise reset a siloed provisioning, which creates a schema and a
// database for every plane, or a verified erasure, while the work keeps
// running server-side and its caller never sees the result.
const (
	provisionWriteBudget = 5 * time.Minute
	eraseWriteBudget     = 15 * time.Minute
)

// extendWriteDeadline lifts the server's WriteTimeout for one response; it is
// best-effort, like the core API's.
func extendWriteDeadline(w http.ResponseWriter, d time.Duration) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d))
}

// The S-T5 provider-side erase view: the CORE lifecycle engine does the
// verifiable deletion (export/erasure is a compliance right, core by the
// ratified decision); the provider plane adds the operator-facing trigger —
// admin SoD, slug-confirmed, audited, with the attestation returned for the
// offboarded customer's records.

// Lifecycle is the core engine surface the provider plane consumes.
type Lifecycle interface {
	Erase(ctx context.Context, tenantID, slug, actor string) (tenantlife.Attestation, error)
}

// WithLifecycle attaches the core engine (always present in real deployments;
// nil only in pool-less tests — then the route answers 503).
func (h *Handler) WithLifecycle(l Lifecycle) *Handler {
	if l != nil {
		h.lifecycle = l
	}
	return h
}

func (h *Handler) handleTenantErase(w http.ResponseWriter, r *http.Request, op Operator) error {
	extendWriteDeadline(w, eraseWriteBudget)
	if h.lifecycle == nil {
		return errConsentNotConfigured // 503 not_configured
	}
	if err := h.svc.CheckWritable(); err != nil {
		return err
	}
	var in struct {
		Confirm string `json:"confirm"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	tenantID := r.PathValue("id")
	// Resolve the slug from the registry; the confirm string must match it.
	tenants, err := h.svc.ListTenants(r.Context())
	if err != nil {
		return err
	}
	slug := ""
	for _, t := range tenants {
		if t.ID == tenantID {
			if t.Status == "provisioning" {
				// No tenant registry row exists yet. The safe operation is to
				// retry provisioning, not run the destructive lifecycle engine
				// against a half-created external silo.
				return ErrConflict
			}
			slug = t.Slug
		}
	}
	if slug == "" {
		return ErrNotFound
	}
	if !strings.EqualFold(strings.TrimSpace(in.Confirm), slug) {
		return errBadJSON{strErr("confirm must equal the tenant slug exactly — erasure is irreversible")}
	}
	att, err := h.lifecycle.Erase(r.Context(), tenantID, slug, "operator:"+op.Email)
	if err != nil {
		return err
	}
	if err := h.svc.RecordTenantErase(r.Context(), op.Email, tenantID, att.Complete, att.ReportSHA256); err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, att)
}

func lifecycleRoutes() []RouteDecl {
	return []RouteDecl{
		{http.MethodPost, "/provider/v1/tenants/{id}/erase"},
	}
}
