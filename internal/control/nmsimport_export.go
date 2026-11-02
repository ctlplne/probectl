// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"mime"
	"net/http"
	"strconv"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/nmsimport"
)

// Export pages are operator-submitted preview evidence. The authenticated
// tenant and authorized routing context own the plan; vendor JSON cannot
// choose either, and no outbound request or destination write occurs here.
func (s *Server) handleStartNMSImportExportPlan(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ContextID   string         `json:"context_id"`
		SourceKind  nmsimport.Kind `json:"source_kind"`
		InstanceRef string         `json:"instance_ref"`
	}
	if err := decodeJSONLimit(r, 8<<10, &req); err != nil {
		return err
	}
	ctx, contextID, err := s.nmsImportContext(r, req.ContextID, permNMSImportWrite)
	if err != nil {
		return err
	}
	planID, err := s.nmsImportCaptureStore(r).StartExportPreviewPlan(ctx,
		contextID, req.SourceKind, req.InstanceRef)
	switch {
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("import routing context not found")
	case errors.Is(err, nmsimport.ErrInvalidPage):
		return apierror.BadRequest("invalid preview source or instance")
	case err != nil:
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"plan_id": planID, "state": "capturing", "preview": true,
	})
	return nil
}

func (s *Server) handleAppendNMSImportExportPage(w http.ResponseWriter, r *http.Request) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return apierror.BadRequest("preview page must be application/json")
	}
	query := r.URL.Query()
	ctx, contextID, err := s.nmsImportContext(r, query.Get("context_id"), permNMSImportWrite)
	if err != nil {
		return err
	}
	pageNumber, err := strconv.ParseInt(query.Get("page_number"), 10, 64)
	if err != nil || pageNumber < 0 {
		return apierror.BadRequest("invalid preview page number")
	}
	firstRow, err := strconv.ParseInt(query.Get("first_row"), 10, 64)
	if err != nil || firstRow < 0 {
		return apierror.BadRequest("invalid preview first row")
	}
	pageHash, err := s.nmsImportCaptureStore(r).AppendPage(ctx, contextID,
		r.PathValue("id"), pageNumber, query.Get("resource"), firstRow, r.Body)
	switch {
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("preview plan not found in this routing context")
	case errors.Is(err, nmsimport.ErrInvalidPage):
		return apierror.BadRequest("invalid or changed preview page")
	case err != nil:
		return err
	}
	writeJSON(w, http.StatusOK, map[string]string{"page_hash": pageHash})
	return nil
}

func (s *Server) handleSealNMSImportExportPlan(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ContextID     string `json:"context_id"`
		ExpectedPages int64  `json:"expected_pages"`
		ExpectedRows  int64  `json:"expected_rows"`
	}
	if err := decodeJSONLimit(r, 8<<10, &req); err != nil {
		return err
	}
	ctx, contextID, err := s.nmsImportContext(r, req.ContextID, permNMSImportWrite)
	if err != nil {
		return err
	}
	snapshotHash, err := s.nmsImportCaptureStore(r).Seal(ctx, contextID,
		r.PathValue("id"), req.ExpectedPages, req.ExpectedRows)
	switch {
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("preview plan not found in this routing context")
	case errors.Is(err, nmsimport.ErrInvalidPage):
		return apierror.BadRequest("preview page totals or receipts are invalid")
	case err != nil:
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"state": "sealed", "snapshot_hash": snapshotHash, "preview": true,
	})
	return nil
}
