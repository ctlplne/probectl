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
	"strings"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

type saveFlowFilterRequest struct {
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Expression  flow.QueryFilterGroup `json:"expression"`
	Version     int64                 `json:"version,omitempty"`
	VersionText string                `json:"version_text,omitempty"`
}

// flowFilterPrincipal verifies tenant identity before any source permission or
// store lookup, including when a handler is used by an internal transport.
func (s *Server) authorizeFlowFilterPrincipal(ctx context.Context, p *auth.Principal, mutation bool) (*auth.Principal, error) {
	if p == nil || strings.TrimSpace(p.TenantID) == "" {
		return nil, apierror.Unauthorized("tenant identity required")
	}
	permissions := []string{permAIQuery, permFlowRead}
	if mutation {
		permissions = append(permissions, permFlowFiltersWrite)
	}
	resource := map[string]string{auth.ResourceTenantKey: p.TenantID}
	for _, permission := range permissions {
		if err := s.authorize(ctx, p, permission, auth.RBACGlobal, resource); err != nil {
			return nil, err
		}
	}
	if s.flowQueryFilters == nil {
		return nil, apierror.Unavailable("saved flow filters are unavailable")
	}
	return p, nil
}

func mapFlowFilterError(err error) error {
	switch {
	case errors.Is(err, flow.ErrQueryFilterNotFound):
		return apierror.NotFound("saved flow filter not found")
	case errors.Is(err, flow.ErrQueryFilterConflict):
		return apierror.Conflict("saved flow filter changed; refresh its version and retry")
	case errors.Is(err, flow.ErrQueryFilterStorageBudget):
		return apierror.Validation("saved flow filter storage byte budget exceeded")
	default:
		return apierror.Unavailable("saved flow filters are temporarily unavailable")
	}
}

func (s *Server) authorizeSavedFlowFilterContext(ctx context.Context, p *auth.Principal, item flow.SavedQueryFilter) error {
	// Retaining scope in the domain response catches a bad storage adapter.
	if item.TenantID != p.TenantID || item.Version < 1 {
		return apierror.Unavailable("saved flow filter storage scope is unavailable")
	}
	return s.authorizeFlowFilterExpressionContext(ctx, p, &item.Expression, "")
}

func (s *Server) authorizeFlowFilterExpressionContext(ctx context.Context, p *auth.Principal, expression *flow.QueryFilterGroup, updatingID string) error {
	resolved, err := flow.ResolveQueryFilters(ctx, p.TenantID, expression, s.flowQueryFilters, updatingID)
	if err != nil {
		if errors.Is(err, flow.ErrQueryFilterNotFound) {
			return mapFlowFilterError(err)
		}
		// A storage diagnostic must never reflect SQL, credentials or filter literals.
		return apierror.Validation("saved flow filter references are invalid or unavailable within the query bounds")
	}
	return s.authorizeFlowMetadata(ctx, p, flow.QueryPlan{Filter: resolved.Expression})
}

func (s *Server) handleListFlowFilters(w http.ResponseWriter, r *http.Request) error {
	p, err := s.flowFilterPrincipal(r, false)
	if err != nil {
		return err
	}
	limit := 100
	if values, ok := r.URL.Query()["limit"]; ok {
		if len(values) != 1 {
			return apierror.Validation("one page limit is required")
		}
		limit, err = strconv.Atoi(values[0])
		if err != nil {
			return apierror.Validation("saved flow filter page size must be 1-1000")
		}
	}
	page, err := s.listFlowFilters(r.Context(), p, r.URL.Query().Get("after"), limit)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}

func (s *Server) handleGetFlowFilter(w http.ResponseWriter, r *http.Request) error {
	item, err := s.getFlowFilter(r.Context(), auth.PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, item)
	return nil
}

func (s *Server) handleCreateFlowFilter(w http.ResponseWriter, r *http.Request) error {
	return s.saveFlowFilter(w, r, false)
}
func (s *Server) handleUpdateFlowFilter(w http.ResponseWriter, r *http.Request) error {
	return s.saveFlowFilter(w, r, true)
}

func (s *Server) saveFlowFilter(w http.ResponseWriter, r *http.Request, update bool) error {
	p, err := s.flowFilterPrincipal(r, true)
	if err != nil {
		return err
	}
	var request saveFlowFilterRequest
	if err := decodeJSONLimit(r, flow.MaxPlanGrammarBytes, &request); err != nil {
		return err
	}
	if request.VersionText != "" {
		version, err := strconv.ParseInt(request.VersionText, 10, 64)
		if err != nil || version < 1 || strconv.FormatInt(version, 10) != request.VersionText {
			return apierror.Validation("version_text must be an exact positive decimal int64 token")
		}
		if request.Version != 0 && request.Version != version {
			return apierror.Validation("numeric and text filter versions conflict")
		}
		request.Version = version
	}
	input := flow.SaveQueryFilter{Name: request.Name, Description: request.Description, Expression: request.Expression, Version: request.Version}
	if update {
		input.ID = r.PathValue("id")
	}
	item, err := s.saveFlowFilterDefinition(r.Context(), p, input)
	if err != nil {
		return err
	}
	status := http.StatusOK
	if !update {
		status = http.StatusCreated
		w.Header().Set("Location", "/v1/explorer/flow-filters/"+item.ID)
	}
	writeJSON(w, status, item)
	return nil
}

func (s *Server) handleDeleteFlowFilter(w http.ResponseWriter, r *http.Request) error {
	if err := s.deleteFlowFilter(r.Context(), auth.PrincipalFrom(r.Context()), r.PathValue("id"), r.URL.Query()["version"]); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// HTTP wrappers preserve strict wire decoding; native transports call the same
// tenant-first context services without constructing or invoking HTTP handlers.
func (s *Server) flowFilterPrincipal(r *http.Request, mutation bool) (*auth.Principal, error) {
	return s.authorizeFlowFilterPrincipal(r.Context(), auth.PrincipalFrom(r.Context()), mutation)
}

func flowFilterAuditActor(p *auth.Principal) string {
	if p.Email != "" {
		return p.Email
	}
	if p.UserID != "" {
		return p.UserID
	}
	return "unknown"
}
func (s *Server) listFlowFilters(ctx context.Context, p *auth.Principal, after string, limit int) (flow.QueryFilterPage, error) {
	p, err := s.authorizeFlowFilterPrincipal(ctx, p, false)
	if err != nil {
		return flow.QueryFilterPage{}, err
	}
	if len(after) > 128 {
		return flow.QueryFilterPage{}, apierror.Validation("saved flow filter cursor exceeds 128 bytes")
	}
	if limit < 1 || limit > 1000 {
		return flow.QueryFilterPage{}, apierror.Validation("saved flow filter page size must be 1-1000")
	}
	page, err := s.flowQueryFilters.ListQueryFilters(ctx, p.TenantID, after, limit)
	if err != nil {
		return flow.QueryFilterPage{}, mapFlowFilterError(err)
	}
	for _, item := range page.Items {
		if err := s.authorizeSavedFlowFilterContext(ctx, p, item); err != nil {
			return flow.QueryFilterPage{}, err
		}
	}
	return page, nil
}
func (s *Server) getFlowFilter(ctx context.Context, p *auth.Principal, id string) (flow.SavedQueryFilter, error) {
	p, err := s.authorizeFlowFilterPrincipal(ctx, p, false)
	if err != nil {
		return flow.SavedQueryFilter{}, err
	}
	item, err := s.flowQueryFilters.GetQueryFilter(ctx, p.TenantID, id)
	if err != nil {
		return flow.SavedQueryFilter{}, mapFlowFilterError(err)
	}
	if err := s.authorizeSavedFlowFilterContext(ctx, p, item); err != nil {
		return flow.SavedQueryFilter{}, err
	}
	return item, nil
}
func (s *Server) saveFlowFilterDefinition(ctx context.Context, p *auth.Principal, input flow.SaveQueryFilter) (flow.SavedQueryFilter, error) {
	p, err := s.authorizeFlowFilterPrincipal(ctx, p, true)
	if err != nil {
		return flow.SavedQueryFilter{}, err
	}
	if input.ID != "" {
		previous, err := s.flowQueryFilters.GetQueryFilter(ctx, p.TenantID, input.ID)
		if err != nil {
			return flow.SavedQueryFilter{}, mapFlowFilterError(err)
		}
		if previous.TenantID != p.TenantID {
			return flow.SavedQueryFilter{}, apierror.Unavailable("saved flow filter storage scope is unavailable")
		}
	}
	input, err = flow.NormalizeSaveQueryFilter(input)
	if err != nil {
		if errors.Is(err, flow.ErrQueryFilterConflict) || errors.Is(err, flow.ErrQueryFilterStorageBudget) {
			return flow.SavedQueryFilter{}, mapFlowFilterError(err)
		}
		return flow.SavedQueryFilter{}, apierror.Validation(err.Error())
	}
	if err := s.authorizeFlowFilterExpressionContext(ctx, p, &input.Expression, input.ID); err != nil {
		return flow.SavedQueryFilter{}, err
	}
	item, err := s.flowQueryFilters.SaveQueryFilter(ctx, p.TenantID, flowFilterAuditActor(p), input)
	if err != nil {
		return flow.SavedQueryFilter{}, mapFlowFilterError(err)
	}
	if err := s.authorizeSavedFlowFilterContext(ctx, p, item); err != nil {
		return flow.SavedQueryFilter{}, err
	}
	return item, nil
}
func (s *Server) deleteFlowFilter(ctx context.Context, p *auth.Principal, id string, versions []string) error {
	p, err := s.authorizeFlowFilterPrincipal(ctx, p, true)
	if err != nil {
		return err
	}
	// Preserve foreign-ID indistinguishability before version validation.
	item, err := s.flowQueryFilters.GetQueryFilter(ctx, p.TenantID, id)
	if err != nil {
		return mapFlowFilterError(err)
	}
	if item.TenantID != p.TenantID {
		return apierror.Unavailable("saved flow filter storage scope is unavailable")
	}
	if len(versions) != 1 {
		return apierror.Validation("delete requires one observed version")
	}
	version, err := strconv.ParseInt(versions[0], 10, 64)
	if err != nil || version < 1 {
		return apierror.Validation("delete requires a positive observed version")
	}
	if err := s.flowQueryFilters.DeleteQueryFilter(ctx, p.TenantID, flowFilterAuditActor(p), item.ID, version); err != nil {
		return mapFlowFilterError(err)
	}
	return nil
}
