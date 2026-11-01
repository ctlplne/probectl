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

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/nmsimport"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) nmsImportContext(r *http.Request, contextID, permission string) (context.Context, string, error) {
	tenantID, err := s.principalTenant(r)
	if err != nil {
		return nil, "", err
	}
	scope, err := (entity.Scope{TenantID: tenantID, ContextID: contextID}).Normalize()
	if err != nil {
		return nil, "", apierror.BadRequest("invalid import routing context")
	}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(scope.TenantID))
	resource, err := s.entityResource(ctx, scope)
	if err != nil {
		return nil, "", err
	}
	if err := s.authorize(r.Context(), auth.PrincipalFrom(r.Context()),
		permission, auth.RBACGlobal, resource); err != nil {
		return nil, "", err
	}
	return ctx, scope.ContextID, nil
}

// A tenant may nominate an approved HTTPS origin and a reference inside its
// deployment-owned namespace. The policy is not taken from the request. No
// network call or credential resolution occurs during configuration.
func (s *Server) handleConfigureNMSImportSource(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ContextID     string `json:"context_id"`
		InstanceRef   string `json:"instance_ref"`
		Origin        string `json:"https_origin"`
		CredentialRef string `json:"credential_ref"`
	}
	if err := decodeJSONLimit(r, 8<<10, &req); err != nil {
		return err
	}
	ctx, contextID, err := s.nmsImportContext(r, req.ContextID, permNMSImportWrite)
	if err != nil {
		return err
	}
	if s.cfg == nil || len(s.cfg.NMSImportApprovedCIDRs) == 0 || s.cfg.NMSImportRefPrefix == "" {
		return apierror.Unavailable("live NMS import is not configured")
	}
	capturer := nmsimport.NewCaptureStore(s.pool,
		func(ctx context.Context, sc tenancy.Scope, action, target string, data map[string]any) error {
			return s.recordAudit(ctx, sc, r, action, target, data)
		})
	sourceID, err := capturer.ConfigureLibreNMSHTTPSource(ctx, contextID,
		req.InstanceRef, req.Origin, req.CredentialRef, s.cfg.NMSImportRefPrefix,
		s.cfg.NMSImportApprovedCIDRs, s.cfg.NMSImportCAFile, s.cfg.NMSImportTimeout)
	switch {
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("import routing context not found")
	case errors.Is(err, nmsimport.ErrSourceUnavailable):
		return apierror.BadRequest("source refused by deployment policy")
	case err != nil:
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]string{"source_id": sourceID})
	return nil
}

// Disable is idempotent and invalidates in-flight plans through the source
// version. It works even after the deployment removes the outbound policy.
func (s *Server) handleDisableNMSImportSource(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ContextID string `json:"context_id"`
	}
	if err := decodeJSONLimit(r, 8<<10, &req); err != nil {
		return err
	}
	ctx, contextID, err := s.nmsImportContext(r, req.ContextID, permNMSImportWrite)
	if err != nil {
		return err
	}
	capturer := nmsimport.NewCaptureStore(s.pool,
		func(ctx context.Context, sc tenancy.Scope, action, target string, data map[string]any) error {
			return s.recordAudit(ctx, sc, r, action, target, data)
		})
	err = capturer.DisableLibreNMSHTTPSource(ctx, contextID, r.PathValue("instance"))
	switch {
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("import source not found in this routing context")
	case err != nil:
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// A sealed import row is still an inert source candidate. Resolve the stored
// tenant context before RBAC/ABAC, then page only its FORCE-RLS plan rows. A
// foreign context or plan has the same 404 without source-existence clues.
func (s *Server) handleListNMSImportRows(w http.ResponseWriter, r *http.Request) error {
	ctx, contextID, err := s.nmsImportContext(r, r.URL.Query().Get("context_id"), permNMSImportRead)
	if err != nil {
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
		contextID, r.PathValue("id"), after, limit)
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
