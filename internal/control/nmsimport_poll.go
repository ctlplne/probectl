// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/nmsimport"
)

// List only inert applied Zabbix item proposals from one exact source. A
// source item cannot choose a current agent; that separate preview still
// requires entities.read and the operator-assigned target.
func (s *Server) handleListNMSImportPollProposals(w http.ResponseWriter, r *http.Request) error {
	ctx, contextID, err := s.nmsImportContext(r, r.URL.Query().Get("context_id"),
		permNMSImportRead)
	if err != nil {
		return err
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil {
			return apierror.BadRequest("invalid import proposal limit")
		}
	}
	page, err := nmsimport.NewCaptureStore(s.pool, nil).ListPollProposals(ctx,
		contextID, r.URL.Query().Get("source_id"), r.URL.Query().Get("cursor"), limit)
	switch {
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("import source not found in this routing context")
	case errors.Is(err, nmsimport.ErrInvalidPage):
		return apierror.BadRequest("invalid import proposal page")
	case err != nil:
		return err
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}

// This read returns no credential and performs no activation. Explicit
// source/item and agent/target identities are all checked inside one tenant
// transaction before an operator can build a device-agent fragment.
func (s *Server) handlePreviewNMSImportPollTarget(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ContextID     string `json:"context_id"`
		SourceID      string `json:"source_id"`
		ItemID        string `json:"item_external_id"`
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
	preview, err := nmsimport.NewCaptureStore(s.pool, nil).PreviewPollTarget(ctx,
		contextID, req.SourceID, req.ItemID, req.AgentID, req.TargetAddress)
	switch {
	case errors.Is(err, nmsimport.ErrInvalidReview):
		return apierror.BadRequest("invalid poll target selection")
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("current reviewed poll target not found")
	case err != nil:
		return err
	}
	writeJSON(w, http.StatusOK, preview)
	return nil
}
