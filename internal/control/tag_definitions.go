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

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) tagRoutes() []apiRoute {
	return []apiRoute{
		{http.MethodGet, "/v1/tags", s.handleListTagDefinitions, permTagsRead},
		{http.MethodPost, "/v1/tags", s.handleCreateTagDefinition, permTagsWrite},
		{http.MethodPost, "/v1/tags/tests/resolve", s.handleResolveTestTagContext, permTagsRead},
		{http.MethodPut, "/v1/tags/{id}", s.handleRenameTagDefinition, permTagsWrite},
		{http.MethodDelete, "/v1/tags/{id}", s.handleDeleteTagDefinition, permTagsWrite},
		{http.MethodGet, "/v1/entity-contexts/{context_id}/tag-rules", s.handleListTagRules, permTagsRead},
		{http.MethodPost, "/v1/entity-contexts/{context_id}/tag-rules", s.handleCreateTagRule, permTagsWrite},
		{http.MethodPut, "/v1/entity-contexts/{context_id}/tag-rules/{id}", s.handleUpdateTagRule, permTagsWrite},
		{http.MethodDelete, "/v1/entity-contexts/{context_id}/tag-rules/{id}", s.handleDeleteTagRule, permTagsWrite},
		{http.MethodGet, "/v1/entity-contexts/{context_id}/tag-assignments", s.handleListTagAssignments, permTagsRead},
		{http.MethodGet, "/v1/entity-contexts/{context_id}/resolved-tags", s.handleResolveSubjectTags, permTagsRead},
		{http.MethodPost, "/v1/entity-contexts/{context_id}/tag-assignments", s.handleCreateManualTagAssignment, permTagsWrite},
		{http.MethodPut, "/v1/entity-contexts/{context_id}/tag-assignments/{id}", s.handleUpdateManualTagAssignment, permTagsWrite},
		{http.MethodDelete, "/v1/entity-contexts/{context_id}/tag-assignments/{id}", s.handleDeleteManualTagAssignment, permTagsWrite},
		{http.MethodPost, "/v1/entity-contexts/{context_id}/tag-imports/netbox/preview", s.handlePreviewNetBoxTag, permTagsRead},
		{http.MethodPost, "/v1/entity-contexts/{context_id}/tag-imports/netbox/apply", s.handleApplyNetBoxTag, permTagsWrite},
	}
}

// Tag vocabulary is tenant-wide. Route RBAC is checked before these handlers;
// each store operation still runs inside the principal's FORCE-RLS transaction.
// Mutations and their audit events commit or roll back together.
func (s *Server) handleListTagDefinitions(w http.ResponseWriter, r *http.Request) error {
	var items []tags.Definition
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		items, err = (store.TagDefinitions{}).List(ctx, sc)
		return err
	}); err != nil {
		return tagDefinitionAPIError(err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) handleCreateTagDefinition(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		Key string `json:"key"`
	}
	if err := decodeJSONLimit(r, 8<<10, &input); err != nil {
		return err
	}
	item, err := s.mutateTagDefinition(r, tagCreate, "", input.Key)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, item)
	return nil
}

func (s *Server) handleRenameTagDefinition(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		Key string `json:"key"`
	}
	if err := decodeJSONLimit(r, 8<<10, &input); err != nil {
		return err
	}
	item, err := s.mutateTagDefinition(r, tagUpdate, r.PathValue("id"), input.Key)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, item)
	return nil
}

func (s *Server) handleDeleteTagDefinition(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.mutateTagDefinition(r, tagDelete, r.PathValue("id"), ""); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func tagDefinitionAPIError(err error) error {
	switch {
	case errors.Is(err, tags.ErrInvalid):
		return apierror.BadRequest("invalid tag key or tenant tag quota reached")
	case errors.Is(err, tags.ErrConflict):
		return apierror.Conflict("tag key already exists in this tenant")
	case errors.Is(err, pgx.ErrNoRows):
		return apierror.NotFound("tag definition does not exist in this tenant")
	default:
		return err
	}
}
