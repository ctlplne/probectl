// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/nmsimport"
)

// An alert source selector is never a target assignment. This read checks
// the exact current operator-owned agent/target binding and returns only an
// inert finite proposal. Native alert creation is a separate reviewed write.
func (s *Server) handlePreviewNMSImportAlertTarget(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ContextID     string `json:"context_id"`
		SourceID      string `json:"source_id"`
		RuleID        string `json:"rule_external_id"`
		AgentID       string `json:"agent_id"`
		TargetAddress string `json:"target_address"`
	}
	if err := decodeJSONLimit(r, 8<<10, &req); err != nil {
		return err
	}
	ctx, contextID, err := s.nmsImportContext(r, req.ContextID, permNMSImportRead)
	if err != nil {
		return err
	}
	tenantID, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	resource, err := s.entityResource(ctx,
		entity.Scope{TenantID: tenantID, ContextID: contextID})
	if err != nil {
		return err
	}
	if err := s.authorize(r.Context(), auth.PrincipalFrom(r.Context()),
		ai.PermEntitiesRead, auth.RBACGlobal, resource); err != nil {
		return err
	}
	preview, err := nmsimport.NewCaptureStore(s.pool, nil).PreviewLibreNMSAlertTarget(ctx,
		contextID, req.SourceID, req.RuleID, req.AgentID, req.TargetAddress)
	switch {
	case errors.Is(err, nmsimport.ErrInvalidReview):
		return apierror.BadRequest("invalid alert target selection")
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("current finite alert target not found")
	case err != nil:
		return err
	}
	writeJSON(w, http.StatusOK, preview)
	return nil
}

// The operator submits the exact plan, snapshot and canonical target shown
// by preview. The import and alert write permissions are both required; a
// file snapshot stays offline, while a configured source gets one bounded
// rules-endpoint freshness read before the disabled native write.
func (s *Server) handleApplyNMSImportAlertTarget(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ContextID     string `json:"context_id"`
		SourceID      string `json:"source_id"`
		RuleID        string `json:"rule_external_id"`
		AgentID       string `json:"agent_id"`
		TargetAddress string `json:"target_address"`
		PlanID        string `json:"plan_id"`
		SnapshotHash  string `json:"snapshot_hash"`
		EntityID      string `json:"entity_id"`
	}
	if err := decodeJSONLimit(r, 8<<10, &req); err != nil {
		return err
	}
	ctx, contextID, err := s.nmsImportContext(r, req.ContextID, permNMSImportWrite)
	if err != nil {
		return err
	}
	tenantID, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	resource, err := s.entityResource(ctx,
		entity.Scope{TenantID: tenantID, ContextID: contextID})
	if err != nil {
		return err
	}
	principal := auth.PrincipalFrom(r.Context())
	for _, permission := range []string{ai.PermEntitiesRead, permAlertWrite} {
		if err := s.authorize(r.Context(), principal, permission,
			auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	result, err := s.nmsImportCaptureStore(r).ApplyLibreNMSAlertTarget(ctx,
		contextID, req.SourceID, req.RuleID, req.AgentID, req.TargetAddress,
		req.PlanID, req.SnapshotHash, req.EntityID, s.nmsImportAlertFetchPolicy())
	switch {
	case errors.Is(err, nmsimport.ErrInvalidReview):
		return apierror.BadRequest("invalid alert import selection")
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("current finite alert target not found")
	case errors.Is(err, nmsimport.ErrReviewStale), errors.Is(err, nmsimport.ErrSourceDrift):
		return apierror.Conflict("reviewed alert source or target changed")
	case errors.Is(err, nmsimport.ErrSourceUnavailable):
		return apierror.Unavailable("configured import source is unavailable")
	case errors.Is(err, nmsimport.ErrInvalidPage):
		return apierror.Conflict("reviewed alert source is invalid")
	case err != nil:
		return err
	}
	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
	}
	writeJSON(w, status, result)
	return nil
}

func (s *Server) nmsImportAlertFetchPolicy() nmsimport.LibreNMSFetchPolicy {
	policy := nmsimport.LibreNMSFetchPolicy{}
	if s.cfg != nil && len(s.cfg.NMSImportApprovedCIDRs) > 0 &&
		s.cfg.NMSImportRefPrefix != "" {
		if resolver, ok := s.secretsHealth.(nmsimport.SourceTokenResolver); ok {
			policy = nmsimport.LibreNMSFetchPolicy{
				ApprovedCIDRs:    s.cfg.NMSImportApprovedCIDRs,
				CAFile:           s.cfg.NMSImportCAFile,
				AllowedRefPrefix: s.cfg.NMSImportRefPrefix,
				Resolver:         resolver,
				Timeout:          min(s.cfg.NMSImportTimeout, 10*time.Second),
			}
		}
	}
	return policy
}
