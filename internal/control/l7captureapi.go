// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/l7redact"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The tenant's L7 capture redaction floor (D-43) is a CORE tenant setting
// (D-64: the headers/full opt-in is a free privacy control, never license
// gated). One route, one column (tenant_governance.l7_capture_redaction, the
// single source of truth): the ee/ governance policy and the provider plane
// never write it. The tenant comes from the authenticated principal, the
// change is audited OLD/NEW on the tenant's hash-chained stream in the same
// transaction, and the regulated profile refuses the opt-ins.

// l7CapturePolicyAuditAction is the tenant-chain audit action for a change.
const l7CapturePolicyAuditAction = "ebpf.l7_capture_policy_set"

// l7CapturePolicyStore is the core store the handlers need (govern.PolicyStore;
// a fake drives the unit tests).
type l7CapturePolicyStore interface {
	TenantL7CaptureRedaction(ctx context.Context, tenantID string) (string, error)
	SetTenantL7CaptureRedaction(ctx context.Context, tenantID, mode, by string, auditTx func(context.Context, tenancy.Scope) error) error
}

func (s *Server) l7CapturePolicies() (l7CapturePolicyStore, error) {
	if s.l7policies != nil {
		return s.l7policies, nil
	}
	if s.pool == nil {
		return nil, apierror.Unavailable("the L7 capture policy needs the control-plane database")
	}
	return govern.NewPolicyStore(s.pool), nil
}

func (s *Server) regulatedProfile() bool {
	return s.cfg != nil && s.cfg.DeploymentProfile == "regulated"
}

func (s *Server) l7CapturePolicyView(stmt string) map[string]any {
	profile := "single"
	if s.cfg != nil && s.cfg.DeploymentProfile != "" {
		profile = s.cfg.DeploymentProfile
	}
	mode := l7redact.Normalize(stmt)
	if !l7redact.ValidMode(mode) {
		mode = l7redact.DefaultMode
	}
	return map[string]any{
		"redaction":          mode,
		"effective_floor":    govern.EffectiveL7CaptureFloor(stmt, s.regulatedProfile()),
		"deployment_profile": profile,
	}
}

// validL7CaptureRedaction checks a requested floor: one of the four modes;
// under the regulated profile only metadata or length (its ingest strip
// enforces metadata for every tenant regardless, so an opt-in would mislead).
func validL7CaptureRedaction(mode string, regulated bool) error {
	if !l7redact.ValidMode(mode) {
		return apierror.Validation("redaction must be one of: length, metadata, headers, full")
	}
	if regulated && l7redact.Looser(mode, l7redact.ModeMetadata) {
		return apierror.Validation("redaction " + mode + " is refused under the regulated deployment profile (D-43): only metadata or length")
	}
	return nil
}

// handleL7CapturePolicyGet serves GET /v1/ebpf/l7-capture-policy.
func (s *Server) handleL7CapturePolicyGet(w http.ResponseWriter, r *http.Request) error {
	st, err := s.l7CapturePolicies()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	stmt, err := st.TenantL7CaptureRedaction(r.Context(), tid)
	if err != nil {
		return apierror.Internal("L7 capture policy read failed").Wrap(err)
	}
	writeJSON(w, http.StatusOK, s.l7CapturePolicyView(stmt))
	return nil
}

// handleL7CapturePolicyPut serves PUT /v1/ebpf/l7-capture-policy.
func (s *Server) handleL7CapturePolicyPut(w http.ResponseWriter, r *http.Request) error {
	st, err := s.l7CapturePolicies()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var in struct {
		Redaction *string `json:"redaction"`
	}
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if in.Redaction == nil {
		// Never reset an opt-in by omission (review note N4).
		return apierror.Validation("redaction is required (length, metadata, headers or full)")
	}
	mode := *in.Redaction
	if err := validL7CaptureRedaction(mode, s.regulatedProfile()); err != nil {
		return err
	}
	prior, err := st.TenantL7CaptureRedaction(r.Context(), tid)
	if err != nil {
		return apierror.Internal("L7 capture policy read failed").Wrap(err)
	}
	actor := auditActor(r)
	auditTx := func(ctx context.Context, sc tenancy.Scope) error {
		data := s.withRequestContext(r, map[string]any{
			"redaction":       mode,
			"prior_redaction": l7redact.Normalize(prior),
			"effective_floor": govern.EffectiveL7CaptureFloor(mode, s.regulatedProfile()),
		}, "success")
		_, e := audit.TenantAppend(ctx, sc, actor, l7CapturePolicyAuditAction, tid, data)
		return e
	}
	if err := st.SetTenantL7CaptureRedaction(r.Context(), tid, mode, actor, auditTx); err != nil {
		return apierror.Internal("L7 capture policy update failed").Wrap(err)
	}
	writeJSON(w, http.StatusOK, s.l7CapturePolicyView(mode))
	return nil
}
