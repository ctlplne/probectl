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
	"time"

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

func (s *Server) nmsImportCaptureStore(r *http.Request) nmsimport.CaptureStore {
	return nmsimport.NewCaptureStore(s.pool,
		func(ctx context.Context, sc tenancy.Scope, action, target string, data map[string]any) error {
			return s.recordAudit(ctx, sc, r, action, target, data)
		})
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
	sourceID, err := s.nmsImportCaptureStore(r).ConfigureLibreNMSHTTPSource(ctx, contextID,
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
	err = s.nmsImportCaptureStore(r).DisableLibreNMSHTTPSource(ctx, contextID, r.PathValue("instance"))
	switch {
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("import source not found in this routing context")
	case err != nil:
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// A live plan binds an enabled source/version inside the tenant transaction;
// starting it never resolves credentials or contacts the source. Its rows
// remain inert until a separate complete capture and human review.
func (s *Server) handleStartNMSImportLivePlan(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ContextID   string `json:"context_id"`
		InstanceRef string `json:"instance_ref"`
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
	planID, err := s.nmsImportCaptureStore(r).StartConfiguredLibreNMSPlan(ctx,
		contextID, req.InstanceRef)
	switch {
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("enabled import source not found in this routing context")
	case errors.Is(err, nmsimport.ErrInvalidPage):
		return apierror.BadRequest("invalid import source instance")
	case err != nil:
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]string{"plan_id": planID, "state": "capturing"})
	return nil
}

// One authenticated request fetches only the server-selected next endpoint.
// The source policy and credential resolver are deployment-owned, while the
// tenant and routing context come from the principal and FORCE-RLS context.
func (s *Server) handleAdvanceNMSImportLivePlan(w http.ResponseWriter, r *http.Request) error {
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
	if s.cfg == nil || len(s.cfg.NMSImportApprovedCIDRs) == 0 || s.cfg.NMSImportRefPrefix == "" {
		return apierror.Unavailable("live NMS import is not configured")
	}
	resolver, ok := s.secretsHealth.(nmsimport.SourceTokenResolver)
	if !ok {
		return apierror.Unavailable("live NMS import credential resolver is unavailable")
	}
	// Leave time for tenant page/audit transactions inside the listener's
	// 15-second write deadline even when a deployment permits slower fetches.
	fetchTimeout := min(s.cfg.NMSImportTimeout, 10*time.Second)
	progress, err := s.nmsImportCaptureStore(r).CaptureNextConfiguredLibreNMSStage(ctx,
		contextID, r.PathValue("id"), nmsimport.LibreNMSFetchPolicy{
			ApprovedCIDRs: s.cfg.NMSImportApprovedCIDRs, CAFile: s.cfg.NMSImportCAFile,
			AllowedRefPrefix: s.cfg.NMSImportRefPrefix, Resolver: resolver,
			Timeout: fetchTimeout})
	switch {
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("import plan not found in this routing context")
	case errors.Is(err, nmsimport.ErrCaptureBusy):
		return apierror.Conflict("import capture step is already running")
	case errors.Is(err, nmsimport.ErrSourceUnavailable):
		return apierror.Unavailable("configured import source is unavailable")
	case errors.Is(err, nmsimport.ErrInvalidPage):
		return apierror.Conflict("source inventory changed or is invalid; capture remains inert")
	case err != nil:
		return err
	}
	writeJSON(w, http.StatusOK, progress)
	return nil
}

// A reviewed plan must re-read every source endpoint before one destination
// chunk is allowed. One request verifies only the server-selected next
// endpoint; the source never supplies the tenant, target or cursor.
func (s *Server) handleVerifyNMSImportBeforeApply(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ContextID    string `json:"context_id"`
		SnapshotHash string `json:"snapshot_hash"`
		ReviewHash   string `json:"review_hash"`
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
	resolver, ok := s.secretsHealth.(nmsimport.SourceTokenResolver)
	if !ok {
		return apierror.Unavailable("live NMS import credential resolver is unavailable")
	}
	// Reserve time for the tenant receipt and audit transaction within the
	// listener's write deadline, just as the initial capture route does.
	fetchTimeout := min(s.cfg.NMSImportTimeout, 10*time.Second)
	progress, err := s.nmsImportCaptureStore(r).VerifyNextConfiguredLibreNMSForApply(ctx,
		contextID, r.PathValue("id"), req.SnapshotHash, req.ReviewHash,
		nmsimport.LibreNMSFetchPolicy{
			ApprovedCIDRs: s.cfg.NMSImportApprovedCIDRs, CAFile: s.cfg.NMSImportCAFile,
			AllowedRefPrefix: s.cfg.NMSImportRefPrefix, Resolver: resolver,
			Timeout: fetchTimeout})
	switch {
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("reviewed import plan not found in this routing context")
	case errors.Is(err, nmsimport.ErrCaptureBusy):
		return apierror.Conflict("import source verification is already running")
	case errors.Is(err, nmsimport.ErrSourceDrift):
		return apierror.Conflict("reviewed source inventory changed; plan is stale")
	case errors.Is(err, nmsimport.ErrInvalidPage):
		return apierror.Conflict("reviewed source inventory is invalid; plan remains inert")
	case errors.Is(err, nmsimport.ErrSourceUnavailable):
		return apierror.Unavailable("configured import source is unavailable")
	case err != nil:
		return err
	}
	writeJSON(w, http.StatusOK, progress)
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

// A finalized dry run reads the frozen operator choices and current exact
// destination targets in one FORCE-RLS tenant transaction. A changed target
// refuses the page; no source address or label is used to choose an entity.
func (s *Server) handleListNMSImportDryRun(w http.ResponseWriter, r *http.Request) error {
	ctx, contextID, err := s.nmsImportContext(r, r.URL.Query().Get("context_id"), permNMSImportRead)
	if err != nil {
		return err
	}
	limit := 50
	if text := r.URL.Query().Get("limit"); text != "" {
		limit, err = strconv.Atoi(text)
		if err != nil {
			return apierror.BadRequest("invalid import dry-run limit")
		}
	}
	after := int64(-1)
	if text := r.URL.Query().Get("cursor"); text != "" {
		after, err = strconv.ParseInt(text, 10, 64)
		if err != nil {
			return apierror.BadRequest("invalid import dry-run cursor")
		}
	}
	page, err := nmsimport.NewCaptureStore(s.pool, nil).ListReviewDiff(ctx,
		contextID, r.PathValue("id"), r.URL.Query().Get("review_hash"), after, limit)
	switch {
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("reviewed import plan not found in this routing context")
	case errors.Is(err, nmsimport.ErrInvalidPage):
		return apierror.BadRequest("invalid import dry-run page")
	case errors.Is(err, nmsimport.ErrReviewStale):
		return apierror.Conflict("reviewed import destination changed")
	case err != nil:
		return err
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}

// Review choices are operator-authored, bounded and bound to the exact sealed
// snapshot. The source cannot request a destination action or target entity.
func (s *Server) handleSetNMSImportReviewChoices(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ContextID    string                   `json:"context_id"`
		SnapshotHash string                   `json:"snapshot_hash"`
		Choices      []nmsimport.ReviewChoice `json:"choices"`
	}
	if err := decodeJSONLimit(r, 32<<10, &req); err != nil {
		return err
	}
	ctx, contextID, err := s.nmsImportContext(r, req.ContextID, permNMSImportWrite)
	if err != nil {
		return err
	}
	err = s.nmsImportCaptureStore(r).SetReviewChoices(ctx, contextID,
		r.PathValue("id"), req.SnapshotHash, req.Choices)
	switch {
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("sealed import plan not found in this routing context")
	case errors.Is(err, nmsimport.ErrInvalidReview):
		return apierror.BadRequest("invalid import review choice")
	case err != nil:
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// Finalization requires every row to have an explicit choice, then freezes a
// hash of the choice set. It still performs no destination write.
func (s *Server) handleFinalizeNMSImportReview(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ContextID    string `json:"context_id"`
		SnapshotHash string `json:"snapshot_hash"`
	}
	if err := decodeJSONLimit(r, 8<<10, &req); err != nil {
		return err
	}
	ctx, contextID, err := s.nmsImportContext(r, req.ContextID, permNMSImportWrite)
	if err != nil {
		return err
	}
	hash, err := s.nmsImportCaptureStore(r).FinalizeReview(ctx, contextID,
		r.PathValue("id"), req.SnapshotHash)
	switch {
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("sealed import plan not found in this routing context")
	case errors.Is(err, nmsimport.ErrInvalidReview):
		return apierror.BadRequest("invalid import review request")
	case errors.Is(err, nmsimport.ErrReviewIncomplete):
		return apierror.Conflict("import review has unassigned rows")
	case err != nil:
		return err
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": "preview", "review_hash": hash})
	return nil
}
