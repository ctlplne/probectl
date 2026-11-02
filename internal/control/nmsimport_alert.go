// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"net/http"

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
