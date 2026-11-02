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
	var req struct {
		Key string `json:"key"`
	}
	if err := decodeJSONLimit(r, 8<<10, &req); err != nil {
		return err
	}
	var item tags.Definition
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		item, err = (store.TagDefinitions{}).Create(ctx, sc, req.Key)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "tag.definition.created", item.ID,
			map[string]any{"key": item.Key})
	})
	if err != nil {
		return tagDefinitionAPIError(err)
	}
	writeJSON(w, http.StatusCreated, item)
	return nil
}

func (s *Server) handleRenameTagDefinition(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Key string `json:"key"`
	}
	if err := decodeJSONLimit(r, 8<<10, &req); err != nil {
		return err
	}
	var item tags.Definition
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		item, err = (store.TagDefinitions{}).Rename(ctx, sc, r.PathValue("id"), req.Key)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "tag.definition.renamed", item.ID,
			map[string]any{"key": item.Key})
	})
	if err != nil {
		return tagDefinitionAPIError(err)
	}
	writeJSON(w, http.StatusOK, item)
	return nil
}

func (s *Server) handleDeleteTagDefinition(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if err := (store.TagDefinitions{}).Delete(ctx, sc, id); err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "tag.definition.deleted", id, nil)
	})
	if err != nil {
		return tagDefinitionAPIError(err)
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
