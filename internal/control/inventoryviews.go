// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"errors"
	"net/http"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/inventory"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

type inventoryViewCreateRequest struct {
	Surface string            `json:"surface"`
	Name    string            `json:"name"`
	Filters map[string]string `json:"filters"`
}

// WithInventoryViews attaches the tenant-scoped saved-view store. nil is a
// no-op; New installs the in-memory lightweight store by default.
func (s *Server) WithInventoryViews(store inventory.ViewStore) *Server {
	if store != nil {
		s.inventoryViews = store
	}
	return s
}

func (s *Server) viewStore() inventory.ViewStore {
	if s.inventoryViews == nil {
		s.inventoryViews = inventory.NewMemoryViewStore()
	}
	return s.inventoryViews
}

// handleListInventoryViews lists the caller tenant's reusable saved list views.
func (s *Server) handleListInventoryViews(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	views, err := s.viewStore().List(r.Context(), tid, savedViewOwner(r), r.URL.Query().Get("surface"))
	if err != nil {
		return mapInventoryViewError(err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views})
	return nil
}

// handleGetInventoryView opens one saved view inside the caller tenant.
func (s *Server) handleGetInventoryView(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	view, err := s.viewStore().Get(r.Context(), tid, savedViewOwner(r), r.PathValue("id"))
	if err != nil {
		return mapInventoryViewError(err)
	}
	writeJSON(w, http.StatusOK, view)
	return nil
}

// handleCreateInventoryView persists one saved view under the caller tenant.
func (s *Server) handleCreateInventoryView(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var req inventoryViewCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	view, err := s.viewStore().Save(r.Context(), tid, savedViewOwner(r), inventory.SaveViewInput{
		Surface: req.Surface,
		Name:    req.Name,
		Filters: req.Filters,
	})
	if err != nil {
		return mapInventoryViewError(err)
	}
	if s.pool != nil {
		if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			return s.recordAudit(ctx, sc, r, "inventory.view.create", view.ID, map[string]any{
				"surface": view.Surface,
				"name":    view.Name,
			})
		}); err != nil {
			return err
		}
	}
	w.Header().Set("Location", "/v1/inventory/views/"+view.ID)
	writeJSON(w, http.StatusCreated, view)
	return nil
}

func savedViewOwner(r *http.Request) string {
	if p := auth.PrincipalFrom(r.Context()); p != nil {
		if p.UserID != "" {
			return p.UserID
		}
		if p.Email != "" {
			return p.Email
		}
	}
	return "unknown"
}

func mapInventoryViewError(err error) error {
	if errors.Is(err, inventory.ErrNotFound) {
		return apierror.NotFound("saved view not found")
	}
	return apierror.Validation(err.Error())
}
