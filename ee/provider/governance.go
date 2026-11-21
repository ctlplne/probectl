// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The S-EE3 governance surface on the provider plane: the per-tenant
// data-governance policy (classification + redaction) AND the COMPOSED
// governance view that pulls together the slices already shipped —
// retention (S-T5), residency (S-T2/S-EE2), and BYOK (S-T6) — so an operator
// sees one place for a tenant's data governance. Attached only when the
// `governance` feature is licensed; absent, the routes 404 (hidden).

// GovernanceStore is the policy store the handler needs (implemented by
// ee/governance.Store over Postgres; a memstore drives the unit tests).
type GovernanceStore interface {
	PolicyFor(ctx context.Context, tenantID string) (govern.Policy, bool, error)
	ChangeAudited(ctx context.Context, tenantID, by string,
		change func(govern.Policy) (govern.Policy, error),
		auditTx func(context.Context, tenancy.Querier, govern.Policy, bool, govern.Policy) error) error
}

// Governance bundles the ee/ governance capability for the handler.
type Governance struct {
	Store         GovernanceStore // classification + redaction policy
	Pool          *pgxpool.Pool   // for the composed retention/residency/BYOK reads (nil in unit tests)
	providerQuery func(context.Context, func(context.Context, tenancy.Querier) error) error
}

// composed is the unified governance view for a tenant.
type composed struct {
	Classifications map[string]string `json:"classifications"` // category -> class (effective)
	RedactFrom      string            `json:"redact_from"`
	RedactExport    bool              `json:"redact_export"`
	AIRemoteEgress  bool              `json:"ai_remote_egress"`         // U-013: remote-AI telemetry consent (AUD-11: now visible on read)
	Residency       string            `json:"residency,omitempty"`      // S-T2/S-EE2
	IsolationModel  string            `json:"isolation_model"`          // S-T2
	RetentionDays   *int              `json:"retention_days,omitempty"` // S-T5
	BYOK            string            `json:"byok,omitempty"`           // S-T6: managed|byok|none
}

func (h *Handler) handleGovernanceView(w http.ResponseWriter, r *http.Request, _ Operator) error {
	if h.governance == nil || h.governance.Store == nil {
		return ErrNotFound
	}
	tenantID := r.PathValue("id")
	pol, _, err := h.governance.Store.PolicyFor(r.Context(), tenantID)
	if err != nil {
		return err
	}
	view := composed{
		Classifications: map[string]string{},
		RedactExport:    pol.RedactExport,
		AIRemoteEgress:  pol.AIRemoteEgress,
		BYOK:            "none",
	}
	if pol.RedactFrom != govern.ClassUnset {
		view.RedactFrom = pol.RedactFrom.String()
	} else {
		view.RedactFrom = govern.ClassPII.String() // the deployment default
	}
	// The EFFECTIVE classification for every known category (defaults + the
	// tenant's overrides) — the governance view shows the full picture.
	for _, cat := range govern.Categories() {
		view.Classifications[string(cat)] = pol.ClassOf(cat).String()
	}
	// Compose residency/isolation/retention/BYOK from their owners (read-only).
	if h.governance.Pool != nil || h.governance.providerQuery != nil {
		run := h.governance.providerQuery
		if run == nil {
			run = func(ctx context.Context, fn func(context.Context, tenancy.Querier) error) error {
				return tenancy.InProvider(ctx, h.governance.Pool, fn)
			}
		}
		if err := run(r.Context(), func(ctx context.Context, q tenancy.Querier) error {
			if err := q.QueryRow(ctx, `SELECT coalesce(residency,''), coalesce(isolation_model,'pooled') FROM tenants WHERE id = $1`, tenantID).
				Scan(&view.Residency, &view.IsolationModel); err != nil {
				return fmt.Errorf("governance tenant metadata: %w", err)
			}
			var days *int
			if err := q.QueryRow(ctx, `SELECT flow_retention_days FROM tenant_retention WHERE tenant_id = $1`, tenantID).Scan(&days); err == nil {
				view.RetentionDays = days
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("governance retention: %w", err)
			}
			var mode string
			if err := q.QueryRow(ctx, `SELECT mode FROM tenant_keys WHERE tenant_id = $1 AND state = 'active'`, tenantID).Scan(&mode); err == nil && mode != "" {
				view.BYOK = mode
			} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("governance byok: %w", err)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return h.writeJSON(w, http.StatusOK, view)
}

func (h *Handler) handlePutGovernance(w http.ResponseWriter, r *http.Request, op Operator) error {
	if h.governance == nil || h.governance.Store == nil {
		return ErrNotFound
	}
	if err := h.svc.CheckWritable(); err != nil {
		return err // the read-only license degrade blocks policy writes too
	}
	var in struct {
		Overrides    map[string]string `json:"classifications"`
		RedactFrom   string            `json:"redact_from"`
		RedactExport bool              `json:"redact_export"`
		// AUD-11: ai_remote_egress is the TENANT's consent to send its telemetry
		// to remote AI models. A provider/MSP operator must NOT set or weaken it
		// from this console (that would exfiltrate a tenant's telemetry without
		// the tenant's consent); only a tenant admin sets it via the tenant-side
		// /v1/governance/policy route. A *bool lets us tell "omitted" (preserve
		// the tenant's value) apart from an explicit change attempt (refused).
		AIRemoteEgress *bool `json:"ai_remote_egress"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	pol := govern.Policy{RedactExport: in.RedactExport, RedactFrom: govern.ParseClass(in.RedactFrom)}
	if in.RedactFrom != "" && pol.RedactFrom == govern.ClassUnset {
		return errBadJSON{strErr("redact_from must be one of: public, internal, confidential, pii, restricted")}
	}
	if in.Overrides != nil {
		pol.Overrides = map[govern.Category]govern.Class{}
		for cat, cls := range in.Overrides {
			c := govern.ParseClass(cls)
			if c == govern.ClassUnset {
				return errBadJSON{strErr("invalid class for category " + cat)}
			}
			pol.Overrides[govern.Category(cat)] = c
		}
	}
	tenantID := r.PathValue("id")
	if err := h.governance.Store.ChangeAudited(r.Context(), tenantID, op.Email,
		func(prior govern.Policy) (govern.Policy, error) {
			// AUD-11: only the tenant can change its AI egress consent. Use
			// the locked current value so a concurrent revocation survives.
			if in.AIRemoteEgress != nil && *in.AIRemoteEgress != prior.AIRemoteEgress {
				return govern.Policy{}, errForbiddenConsent
			}
			next := pol
			next.AIRemoteEgress = prior.AIRemoteEgress
			if in.Overrides == nil {
				next.Overrides = prior.Overrides
			}
			return next, nil
		},
		func(ctx context.Context, q tenancy.Querier, prior govern.Policy, priorFound bool, next govern.Policy) error {
			return h.svc.AppendGovernanceAuditTx(ctx, q, op.Email, tenantID, prior, priorFound, next)
		}); err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// governanceRoutes are appended to Routes() (the openapi parity test covers
// the union).
func governanceRoutes() []RouteDecl {
	return []RouteDecl{
		{http.MethodGet, "/provider/v1/tenants/{id}/governance"},
		{http.MethodPut, "/provider/v1/tenants/{id}/governance"},
	}
}
