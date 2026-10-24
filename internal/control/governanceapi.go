// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Tenant governance policy management (AUD-12, S-EE3 — ee-gated via the
// `governance` Enterprise feature). Governance policy — including the remote-AI
// egress consent (ai_remote_egress) — was manageable ONLY from the MSP-only
// provider plane, so an Enterprise (or Core) tenant admin had to hand-edit SQL
// to grant AI-egress consent or set policy. This is the tenant-scoped twin of
// that provider surface: a tenant admin reads and updates its OWN tenant's
// policy through /v1, RBAC-gated, tenant-scoped at the storage layer (the tenant
// comes from the authenticated principal, never the body — docs/guardrails.md
// G7-1), with the change written to the tamper-evident TENANT audit chain
// (G7-7). It is a MANAGEMENT surface for the existing consent, NOT a relaxation:
// ai_remote_egress stays consent-gated and redacted at the egress path
// (internal/ai, docs/guardrails.md G7-2); this only lets the tenant admin SET
// the consent via an audited API instead of raw SQL.

// governancePolicyStore is the tenant-scoped governance policy store the handler
// needs (implemented by the core govern.PolicyStore over Postgres; a fake drives
// the handler unit tests). Reads and writes are confined to the tenant in ctx.
type governancePolicyStore interface {
	TenantPolicy(ctx context.Context, tenantID string) (govern.Policy, bool, error)
	SetTenantPolicy(ctx context.Context, tenantID string, pol govern.Policy, by string, auditTx func(context.Context, tenancy.Scope) error) error
}

// governancePolicyAuditAction is the tenant-chain audit action for a tenant
// admin's governance policy change (AUD-12, G7-7).
const governancePolicyAuditAction = "governance.policy_set"

// WithGovernance installs the tenant governance policy management store — the
// `governance` Enterprise feature's tenant surface, wired ONLY at the main.go
// Build* attach seam when the feature is licensed. nil leaves the surface hidden
// (404), consistent with the hidden-unlicensed editions UX. Returns the Server
// for chaining, mirroring WithRemediation/WithFairness.
func (s *Server) WithGovernance(store governancePolicyStore) *Server {
	if store != nil {
		s.governance = store
	}
	return s
}

func (s *Server) governanceStore() (governancePolicyStore, error) {
	if s.governance == nil {
		return nil, apierror.NotFound("not found") // hidden-unlicensed
	}
	return s.governance, nil
}

// governancePolicyView renders a tenant's governance policy for the self-view:
// the remote-AI egress consent plus the redaction policy and the EFFECTIVE
// classification of every known category (defaults + the tenant's overrides).
func governancePolicyView(pol govern.Policy) map[string]any {
	classes := make(map[string]string, len(govern.Categories()))
	for _, cat := range govern.Categories() {
		classes[string(cat)] = pol.ClassOf(cat).String()
	}
	return map[string]any{
		"ai_remote_egress": pol.AIRemoteEgress,
		"redact_export":    pol.RedactExport,
		"redact_from":      effectiveRedactFrom(pol),
		"classifications":  classes,
	}
}

// effectiveRedactFrom resolves the policy's redaction floor, defaulting to the
// deployment default (pii) when the tenant left it unset.
func effectiveRedactFrom(pol govern.Policy) string {
	if pol.RedactFrom != govern.ClassUnset {
		return pol.RedactFrom.String()
	}
	return govern.ClassPII.String()
}

func (s *Server) handleGovernancePolicyGet(w http.ResponseWriter, r *http.Request) error {
	store, err := s.governanceStore()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	pol, _, err := store.TenantPolicy(r.Context(), tid)
	if err != nil {
		return apierror.Internal("governance policy read failed").Wrap(err)
	}
	writeJSON(w, http.StatusOK, governancePolicyView(pol))
	return nil
}

func (s *Server) handleGovernancePolicyPut(w http.ResponseWriter, r *http.Request) error {
	store, err := s.governanceStore()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var in struct {
		Overrides      map[string]string `json:"classifications"`
		RedactFrom     string            `json:"redact_from"`
		RedactExport   bool              `json:"redact_export"`
		AIRemoteEgress bool              `json:"ai_remote_egress"`
	}
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	pol := govern.Policy{RedactExport: in.RedactExport, RedactFrom: govern.ParseClass(in.RedactFrom), AIRemoteEgress: in.AIRemoteEgress}
	if in.RedactFrom != "" && pol.RedactFrom == govern.ClassUnset {
		return apierror.Validation("redact_from must be one of: public, internal, confidential, pii, restricted")
	}
	if len(in.Overrides) > 0 {
		pol.Overrides = map[govern.Category]govern.Class{}
		for cat, cls := range in.Overrides {
			c := govern.ParseClass(cls)
			if c == govern.ClassUnset {
				return apierror.Validation("invalid class for category " + cat)
			}
			pol.Overrides[govern.Category(cat)] = c
		}
	}
	// Read the prior policy so the audit receipt records the consent OLD/NEW.
	// The read is tenant-scoped (store confines it to tid), so it cannot leak
	// another tenant's policy.
	prior, priorFound, err := store.TenantPolicy(r.Context(), tid)
	if err != nil {
		return apierror.Internal("governance policy read failed").Wrap(err)
	}
	actor := auditActor(r)
	// The TENANT audit receipt (G7-7), appended in the SAME transaction as the
	// policy write by the store (a failing append rolls the change back). It
	// records who changed the consent, the OLD/NEW ai_remote_egress, and the
	// "from where" request context — never another tenant's data.
	auditTx := func(ctx context.Context, sc tenancy.Scope) error {
		data := s.withRequestContext(r, map[string]any{
			"ai_remote_egress":       pol.AIRemoteEgress,
			"prior_ai_remote_egress": prior.AIRemoteEgress,
			"prior_policy_existed":   priorFound,
			"redact_export":          pol.RedactExport,
			"redact_from":            effectiveRedactFrom(pol),
		}, "success")
		_, e := audit.TenantAppend(ctx, sc, actor, governancePolicyAuditAction, tid, data)
		return e
	}
	if err := store.SetTenantPolicy(r.Context(), tid, pol, actor, auditTx); err != nil {
		if errors.Is(err, license.ErrReadOnly) {
			// The read-only license degrade (govern.GatePolicyWrites): the
			// policy stays readable and the consent can still be withdrawn.
			return apierror.Forbidden(err.Error()).WithCode(string(apierror.CodeLicenseReadOnly))
		}
		return apierror.Internal("governance policy update failed").Wrap(err)
	}
	writeJSON(w, http.StatusOK, governancePolicyView(pol))
	return nil
}
