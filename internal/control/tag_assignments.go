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
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type manualTagAssignmentRequest struct {
	TagID             string `json:"tag_id"`
	TargetKind        string `json:"target_kind"`
	TargetID          string `json:"target_id"`
	ExporterAgentID   string `json:"exporter_agent_id"`
	ExporterSourceRef string `json:"exporter_source_ref"`
	Value             string `json:"value"`
}

func (input manualTagAssignmentRequest) storeInput(tenantID, contextID string) store.ManualTagAssignmentInput {
	return store.ManualTagAssignmentInput{Scope: tags.Scope{
		TenantID: tenantID, ContextID: contextID}, TagID: input.TagID,
		TargetKind: input.TargetKind, TargetID: input.TargetID,
		ExporterAgentID:   input.ExporterAgentID,
		ExporterSourceRef: input.ExporterSourceRef, Value: input.Value}
}

func (s *Server) handleListTagAssignments(w http.ResponseWriter, r *http.Request) error {
	contextID := r.PathValue("context_id")
	if _, err := s.authorizeTagContext(r, contextID, permTagsRead); err != nil {
		return err
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			return apierror.BadRequest("tag assignment limit must be between 1 and 100")
		}
		limit = parsed
	}
	cursor := r.URL.Query().Get("cursor")
	var items []store.TagAssignmentRecord
	var next string
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		items, next, err = (store.TagAssignments{}).List(ctx, sc, contextID, cursor, limit)
		return err
	})
	if err != nil {
		return tagAssignmentAPIError(err)
	}
	page := map[string]any{"items": items}
	if next != "" {
		page["next_cursor"] = next
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}

func (s *Server) handleCreateManualTagAssignment(w http.ResponseWriter, r *http.Request) error {
	contextID := r.PathValue("context_id")
	tenantID, err := s.authorizeTagContext(r, contextID, permTagsWrite)
	if err != nil {
		return err
	}
	var input manualTagAssignmentRequest
	if err := decodeJSONLimit(r, 8<<10, &input); err != nil {
		return err
	}
	var record store.TagAssignmentRecord
	err = s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		record, err = (store.TagAssignments{}).CreateManual(ctx, sc,
			input.storeInput(tenantID, contextID))
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "tag.assignment.created", record.ID,
			map[string]any{"context_id": contextID, "tag_id": record.TagID,
				"target_kind": record.TargetKind, "target_id": record.TargetID})
	})
	if err != nil {
		return tagAssignmentAPIError(err)
	}
	writeJSON(w, http.StatusCreated, record)
	return nil
}

func (s *Server) handleUpdateManualTagAssignment(w http.ResponseWriter, r *http.Request) error {
	contextID := r.PathValue("context_id")
	tenantID, err := s.authorizeTagContext(r, contextID, permTagsWrite)
	if err != nil {
		return err
	}
	var input manualTagAssignmentRequest
	if err := decodeJSONLimit(r, 8<<10, &input); err != nil {
		return err
	}
	var record store.TagAssignmentRecord
	err = s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		record, err = (store.TagAssignments{}).UpdateManual(ctx, sc,
			r.PathValue("id"), input.storeInput(tenantID, contextID))
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "tag.assignment.updated", record.ID,
			map[string]any{"context_id": contextID, "tag_id": record.TagID,
				"target_kind": record.TargetKind, "target_id": record.TargetID})
	})
	if err != nil {
		return tagAssignmentAPIError(err)
	}
	writeJSON(w, http.StatusOK, record)
	return nil
}

func (s *Server) handleDeleteManualTagAssignment(w http.ResponseWriter, r *http.Request) error {
	contextID := r.PathValue("context_id")
	if _, err := s.authorizeTagContext(r, contextID, permTagsWrite); err != nil {
		return err
	}
	id := r.PathValue("id")
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if err := (store.TagAssignments{}).DeleteManual(ctx, sc, contextID, id); err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "tag.assignment.deleted", id,
			map[string]any{"context_id": contextID})
	})
	if err != nil {
		return tagAssignmentAPIError(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func tagAssignmentAPIError(err error) error {
	switch {
	case errors.Is(err, store.ErrTagImportChanged):
		return apierror.Conflict("tag import target or revision changed; request a new preview")
	case errors.Is(err, tags.ErrInvalid):
		return apierror.BadRequest("invalid tag assignment or tenant assignment quota reached")
	case errors.Is(err, tags.ErrScopeMismatch):
		return apierror.BadRequest("invalid tenant routing context")
	case errors.Is(err, store.ErrTagReference), errors.Is(err, pgx.ErrNoRows):
		return apierror.NotFound("tag assignment, key or subject does not exist in this tenant and context")
	case errors.Is(err, tags.ErrConflict):
		return apierror.Conflict("tag assignment already exists for this subject and source")
	default:
		return err
	}
}
