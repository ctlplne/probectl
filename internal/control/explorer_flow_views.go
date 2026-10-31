// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

type saveFlowViewRequest struct {
	Version    string                   `json:"version,omitempty"`
	Definition flow.QueryViewDefinition `json:"definition"`
}

func mapFlowViewError(err error) error {
	switch {
	case errors.Is(err, flow.ErrQueryViewNotFound), errors.Is(err, flow.ErrQueryFilterNotFound):
		return apierror.NotFound("saved flow query not found")
	case errors.Is(err, flow.ErrQueryViewConflict):
		return apierror.Conflict("saved flow query changed; refresh its exact version and retry")
	case errors.Is(err, flow.ErrQueryViewBudget):
		return apierror.Validation("saved flow query storage byte budget exceeded")
	default:
		return apierror.Unavailable("saved flow queries are temporarily unavailable")
	}
}

func (s *Server) authorizeFlowViewPrincipal(ctx context.Context, p *auth.Principal, mutation bool) (*auth.Principal, error) {
	if p == nil || strings.TrimSpace(p.TenantID) == "" || strings.TrimSpace(p.UserID) == "" {
		return nil, apierror.Unauthorized("tenant and user identity required")
	}
	required := []string{permAIQuery, permFlowRead}
	if mutation {
		required = append(required, permFlowViewsWrite)
	}
	for _, permission := range required {
		if err := s.authorize(ctx, p, permission, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: p.TenantID}); err != nil {
			return nil, err
		}
	}
	if s.flowQueryViews == nil {
		return nil, apierror.Unavailable("saved flow query storage is unavailable")
	}
	return p, nil
}

func (s *Server) authorizeFlowViewContext(ctx context.Context, p *auth.Principal, item flow.SavedQueryView) error {
	if item.TenantID != p.TenantID || item.OwnerID == "" {
		return apierror.Unavailable("saved flow query storage scope is unavailable")
	}
	if item.OwnerID != p.UserID && item.Definition.Visibility != "tenant" {
		return apierror.NotFound("saved flow query not found")
	}
	if _, err := flow.QueryViewVersion(item.Version); err != nil {
		return apierror.Unavailable("saved flow query version is unavailable")
	}
	return s.authorizeFlowViewDefinitionContext(ctx, p, item.Definition)
}

func (s *Server) authorizeFlowViewDefinitionContext(ctx context.Context, p *auth.Principal, definition flow.QueryViewDefinition) error {
	plan, _, err := flow.MaterializeQueryView(definition, time.Now())
	if err != nil {
		return apierror.Validation("saved flow query definition is invalid")
	}
	resolved, err := flow.ResolveQueryFilters(ctx, p.TenantID, plan.Filter, s.flowQueryFilters, "")
	if err != nil {
		if errors.Is(err, flow.ErrQueryFilterNotFound) {
			return mapFlowViewError(err)
		}
		return apierror.Validation("saved flow query references are invalid or unavailable")
	}
	plan.Filter = resolved.Expression
	return s.authorizeFlowMetadata(ctx, p, plan)
}

func (s *Server) handleListFlowViews(w http.ResponseWriter, r *http.Request) error {
	p, err := s.flowViewPrincipal(r, false)
	if err != nil {
		return err
	}
	values := r.URL.Query()
	input := flow.QueryViewList{After: values.Get("after"), Search: values.Get("search"), Label: values.Get("label"), Visibility: values.Get("visibility"), Owner: values.Get("owner"), Sort: values.Get("sort"), Tab: values.Get("tab")}
	if value, ok := values["limit"]; ok {
		if len(value) != 1 {
			return apierror.Validation("one saved query page size is required")
		}
		input.Limit, err = strconv.Atoi(value[0])
		if err != nil {
			return apierror.Validation("saved query page size must be1-1000")
		}
	}
	page, err := s.listFlowViews(r.Context(), p, input)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}

func (s *Server) getFlowView(r *http.Request, p *auth.Principal) (flow.SavedQueryView, error) {
	return s.getFlowViewByID(r.Context(), p, r.PathValue("id"))
}

func (s *Server) handleGetFlowView(w http.ResponseWriter, r *http.Request) error {
	p, err := s.flowViewPrincipal(r, false)
	if err != nil {
		return err
	}
	item, err := s.getFlowView(r, p)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, item)
	return nil
}

func (s *Server) handleCreateFlowView(w http.ResponseWriter, r *http.Request) error {
	return s.saveFlowView(w, r, false)
}
func (s *Server) handleUpdateFlowView(w http.ResponseWriter, r *http.Request) error {
	return s.saveFlowView(w, r, true)
}

func (s *Server) saveFlowView(w http.ResponseWriter, r *http.Request, update bool) error {
	p, err := s.flowViewPrincipal(r, true)
	if err != nil {
		return err
	}
	var request saveFlowViewRequest
	if err := decodeJSONLimit(r, flow.MaxPlanGrammarBytes, &request); err != nil {
		return err
	}
	input := flow.SaveQueryView{Version: request.Version, Definition: request.Definition}
	if update {
		input.ID = r.PathValue("id")
	}
	item, err := s.saveFlowViewDefinition(r.Context(), p, input)
	if err != nil {
		return err
	}
	status := http.StatusOK
	if !update {
		status = http.StatusCreated
		w.Header().Set("Location", "/v1/explorer/flow-views/"+item.ID)
	}
	writeJSON(w, status, item)
	return nil
}

func (s *Server) handleDeleteFlowView(w http.ResponseWriter, r *http.Request) error {
	if err := s.deleteFlowView(r.Context(), auth.PrincipalFrom(r.Context()), r.PathValue("id"), r.URL.Query()["version"]); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) handleFlowViewPreference(w http.ResponseWriter, r *http.Request) error {
	p, err := s.flowViewPrincipal(r, false)
	if err != nil {
		return err
	}
	_, err = s.getFlowView(r, p)
	if err != nil {
		return err
	}
	var request struct {
		Favorite *bool `json:"favorite"`
	}
	if err := decodeJSONLimit(r, 1024, &request); err != nil {
		return err
	}
	if request.Favorite == nil {
		return apierror.Validation("favorite is required")
	}
	if err := s.setFlowViewFavorite(r.Context(), p, r.PathValue("id"), request.Favorite); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) handleRunFlowView(w http.ResponseWriter, r *http.Request) error {
	release, err := s.beginQuery(w, r)
	if err != nil {
		return err
	}
	defer release()
	p, err := s.flowViewPrincipal(r, false)
	if err != nil {
		return err
	}
	// Preserve tenant/visibility rejection before examining any override body.
	if _, err := s.getFlowView(r, p); err != nil {
		return err
	}
	if err := validateFlowViewRunBody(r); err != nil {
		return err
	}
	result, err := s.runFlowView(r.Context(), p, r.PathValue("id"))
	if err != nil {
		return err
	}
	switch {
	case result.Comparison != nil:
		writeJSON(w, http.StatusOK, *result.Comparison)
	case result.Query != nil:
		writeJSON(w, http.StatusOK, *result.Query)
	default:
		return apierror.Unavailable("saved flow query execution is unavailable")
	}
	return nil
}
func validateFlowViewRunBody(r *http.Request) error {
	// Execution uses the stored definition. A body cannot smuggle an override.
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1025))
		if err != nil || len(body) > 1024 {
			return apierror.Validation("saved query execution body is invalid")
		}
		if len(bytes.TrimSpace(body)) > 0 {
			var empty struct{}
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&empty); err != nil {
				return apierror.Validation("saved query execution accepts no overrides")
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				return apierror.Validation("saved query execution accepts no overrides")
			}
		}
	}
	return nil
}

type flowViewFilterReader struct{ server *Server }

func (reader flowViewFilterReader) GetQueryFilter(ctx context.Context, tenant, id string) (flow.SavedQueryFilter, error) {
	if reader.server.flowQueryFilters == nil {
		return flow.SavedQueryFilter{}, flow.ErrQueryFilterNotFound
	}
	return reader.server.flowQueryFilters.GetQueryFilter(ctx, tenant, id)
}

// Context services are the shared API/MCP boundary. Transport admission owns
// fairness once; no service adopts tenant, owner or source authority from input.
type flowViewExecution struct {
	Query      *explorerResult
	Comparison *explorerComparisonResult
}

func (s *Server) flowViewPrincipal(r *http.Request, mutation bool) (*auth.Principal, error) {
	return s.authorizeFlowViewPrincipal(r.Context(), auth.PrincipalFrom(r.Context()), mutation)
}

func (s *Server) listFlowViews(ctx context.Context, p *auth.Principal, input flow.QueryViewList) (flow.QueryViewPage, error) {
	p, err := s.authorizeFlowViewPrincipal(ctx, p, false)
	if err != nil {
		return flow.QueryViewPage{}, err
	}
	input, err = flow.NormalizeQueryViewList(input)
	if err != nil {
		return flow.QueryViewPage{}, apierror.Validation(err.Error())
	}
	page, err := s.flowQueryViews.ListQueryViews(ctx, p.TenantID, p.UserID, input)
	if err != nil {
		return flow.QueryViewPage{}, mapFlowViewError(err)
	}
	for _, item := range page.Items {
		if err := s.authorizeFlowViewContext(ctx, p, item); err != nil {
			return flow.QueryViewPage{}, err
		}
	}
	return page, nil
}
func (s *Server) getFlowViewByID(ctx context.Context, p *auth.Principal, id string) (flow.SavedQueryView, error) {
	p, err := s.authorizeFlowViewPrincipal(ctx, p, false)
	if err != nil {
		return flow.SavedQueryView{}, err
	}
	item, err := s.flowQueryViews.GetQueryView(ctx, p.TenantID, p.UserID, id)
	if err != nil {
		return flow.SavedQueryView{}, mapFlowViewError(err)
	}
	if err := s.authorizeFlowViewContext(ctx, p, item); err != nil {
		return flow.SavedQueryView{}, err
	}
	return item, nil
}
func (s *Server) saveFlowViewDefinition(ctx context.Context, p *auth.Principal, input flow.SaveQueryView) (flow.SavedQueryView, error) {
	p, err := s.authorizeFlowViewPrincipal(ctx, p, true)
	if err != nil {
		return flow.SavedQueryView{}, err
	}
	if input.ID != "" {
		previous, err := s.getFlowViewByID(ctx, p, input.ID)
		if err != nil {
			return flow.SavedQueryView{}, err
		}
		if previous.OwnerID != p.UserID {
			return flow.SavedQueryView{}, apierror.NotFound("saved flow query not found")
		}
	}
	input, err = flow.NormalizeSaveQueryView(input, time.Now())
	if err != nil {
		if errors.Is(err, flow.ErrQueryViewConflict) || errors.Is(err, flow.ErrQueryViewBudget) {
			return flow.SavedQueryView{}, mapFlowViewError(err)
		}
		return flow.SavedQueryView{}, apierror.Validation("saved flow query definition is invalid")
	}
	if err := s.authorizeFlowViewDefinitionContext(ctx, p, input.Definition); err != nil {
		return flow.SavedQueryView{}, err
	}
	item, err := s.flowQueryViews.SaveQueryView(ctx, p.TenantID, p.UserID, input)
	if err != nil {
		return flow.SavedQueryView{}, mapFlowViewError(err)
	}
	if err := s.authorizeFlowViewContext(ctx, p, item); err != nil {
		return flow.SavedQueryView{}, err
	}
	return item, nil
}
func (s *Server) deleteFlowView(ctx context.Context, p *auth.Principal, id string, versions []string) error {
	p, err := s.authorizeFlowViewPrincipal(ctx, p, true)
	if err != nil {
		return err
	}
	item, err := s.getFlowViewByID(ctx, p, id)
	if err != nil {
		return err
	}
	if item.OwnerID != p.UserID {
		return apierror.NotFound("saved flow query not found")
	}
	if len(versions) != 1 {
		return apierror.Validation("delete requires one exact observed version")
	}
	if _, err := flow.QueryViewVersion(versions[0]); err != nil {
		return apierror.Validation("delete requires a positive decimal-text version")
	}
	if err := s.flowQueryViews.DeleteQueryView(ctx, p.TenantID, p.UserID, item.ID, versions[0]); err != nil {
		return mapFlowViewError(err)
	}
	return nil
}
func (s *Server) setFlowViewFavorite(ctx context.Context, p *auth.Principal, id string, favorite *bool) error {
	p, err := s.authorizeFlowViewPrincipal(ctx, p, false)
	if err != nil {
		return err
	}
	item, err := s.getFlowViewByID(ctx, p, id)
	if err != nil {
		return err
	}
	if favorite == nil {
		return apierror.Validation("favorite is required")
	}
	if err := s.flowQueryViews.SetQueryViewPreference(ctx, p.TenantID, p.UserID, item.ID, favorite, false); err != nil {
		return mapFlowViewError(err)
	}
	return nil
}
func (s *Server) runFlowView(ctx context.Context, p *auth.Principal, id string) (flowViewExecution, error) {
	p, err := s.authorizeFlowViewPrincipal(ctx, p, false)
	if err != nil {
		return flowViewExecution{}, err
	}
	item, err := s.getFlowViewByID(ctx, p, id)
	if err != nil {
		return flowViewExecution{}, err
	}
	now := time.Now()
	plan, previous, err := flow.MaterializeQueryView(item.Definition, now)
	if err != nil {
		return flowViewExecution{}, apierror.Validation("saved flow query cannot be materialized")
	}
	current, err := ai.NormalizeExplorerQuery(ai.ExplorerQuery{Question: item.Definition.Name, Source: ai.ExplorerFlow, Flow: &plan}, now)
	if err != nil {
		return flowViewExecution{}, apierror.Validation("saved flow query cannot be normalized")
	}
	if err := s.flowQueryViews.SetQueryViewPreference(ctx, p.TenantID, p.UserID, item.ID, nil, true); err != nil {
		return flowViewExecution{}, mapFlowViewError(err)
	}
	if previous == nil {
		result, err := s.recordFlowQuery(ctx, p, current)
		if err != nil {
			return flowViewExecution{}, err
		}
		return flowViewExecution{Query: &result}, nil
	}
	before := current
	before.From = previous.From
	before.To = previous.To
	before.Flow = previous
	before, err = ai.NormalizeExplorerQuery(before, now)
	if err != nil {
		return flowViewExecution{}, apierror.Validation("saved previous period is invalid")
	}
	result, err := s.recordFlowComparison(ctx, p, current, before)
	if err != nil {
		return flowViewExecution{}, err
	}
	return flowViewExecution{Comparison: &result}, nil
}
