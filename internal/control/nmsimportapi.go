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

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/nmsimport"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// A sealed import row is still an inert source candidate. Resolve the stored
// tenant context before RBAC/ABAC, then page only its FORCE-RLS plan rows. A
// foreign context or plan has the same 404 without source-existence clues.
func (s *Server) handleListNMSImportRows(w http.ResponseWriter, r *http.Request) error {
	tenantID, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	scope, err := (entity.Scope{TenantID: tenantID,
		ContextID: r.URL.Query().Get("context_id")}).Normalize()
	if err != nil {
		return apierror.BadRequest("invalid import routing context")
	}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(scope.TenantID))
	resource, err := s.entityResource(ctx, scope)
	if err != nil {
		return err
	}
	if err := s.authorize(r.Context(), auth.PrincipalFrom(r.Context()),
		permNMSImportRead, auth.RBACGlobal, resource); err != nil {
		return err
	}
	limit := 50
	if text := r.URL.Query().Get("limit"); text != "" {
		limit, err = strconv.Atoi(text)
		if err != nil {
			return apierror.BadRequest("invalid import page limit")
		}
	}
	after := int64(-1)
	if text := r.URL.Query().Get("cursor"); text != "" {
		after, err = strconv.ParseInt(text, 10, 64)
		if err != nil {
			return apierror.BadRequest("invalid import page cursor")
		}
	}
	page, err := nmsimport.NewCaptureStore(s.pool, nil).ListSealedRows(ctx,
		scope.ContextID, r.PathValue("id"), after, limit)
	switch {
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("import plan not found in this routing context")
	case errors.Is(err, nmsimport.ErrInvalidPage):
		return apierror.BadRequest("invalid import page")
	case err != nil:
		return err
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}
