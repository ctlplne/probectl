// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type flowSnapshotPaging struct {
	SnapshotID   string    `json:"snapshot_id"`
	ExpiresAt    time.Time `json:"expires_at"`
	SelectedRows int       `json:"selected_rows"`
	Offset       int       `json:"offset"`
	PageSize     int       `json:"page_size"`
	More         bool      `json:"more"`
	NextCursor   string    `json:"next_cursor,omitempty"`
}

func flowSnapshotScope(p *auth.Principal) (flowsnapshot.Scope, error) {
	if p == nil || strings.TrimSpace(p.TenantID) == "" || strings.TrimSpace(p.UserID) == "" {
		return flowsnapshot.Scope{}, apierror.Unauthorized("tenant and user identity required for private flow results")
	}
	return flowsnapshot.Scope{TenantID: p.TenantID, Owner: p.UserID}, nil
}

func (s *Server) flowSnapshotAuthorizer(p *auth.Principal) flowsnapshot.Authorize {
	return func(ctx context.Context, scope flowsnapshot.Scope, required []string) error {
		if p == nil || scope.TenantID != p.TenantID || scope.Owner != p.UserID {
			return apierror.NotFound("flow snapshot not found")
		}
		for _, permission := range required {
			if err := s.authorize(ctx, p, permission, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: scope.TenantID}); err != nil {
				return err
			}
		}
		return nil
	}
}

func flowSnapshotError(err error) error {
	var domain *apierror.Error
	if errors.As(err, &domain) {
		return domain
	}
	switch {
	case errors.Is(err, flowstore.ErrExplorerBudget):
		return flowExplorerStoreError(err)
	case errors.Is(err, flowsnapshot.ErrNotFound):
		return apierror.NotFound("flow snapshot not found or expired; run a fresh query")
	case errors.Is(err, flowsnapshot.ErrCursor):
		return apierror.Validation("flow snapshot cursor is invalid")
	case errors.Is(err, flowsnapshot.ErrBudget):
		return apierror.Validation("flow snapshot storage budget exceeded").WithCode(string(apierror.CodeFlowQueryBudget))
	case errors.Is(err, flowsnapshot.ErrInvalidating):
		return apierror.Unavailable("flow results are unavailable during a tenant lifecycle transition")
	default:
		return apierror.Unavailable("shared flow results are unavailable")
	}
}

func (s *Server) createFlowSnapshot(ctx context.Context, p *auth.Principal, query ai.ExplorerQuery, plan flow.QueryPlan, versions map[string]int64) (explorerResult, error) {
	scope, err := flowSnapshotScope(p)
	if err != nil {
		return explorerResult{}, err
	}
	if s.flowSnapshotSource == nil {
		return explorerResult{}, apierror.Unavailable("flow snapshot source validation is unavailable")
	}
	if s.flowSnapshots == nil {
		return explorerResult{}, apierror.Unavailable("shared flow snapshot storage is unavailable")
	}
	started := time.Now()
	query.Flow = &plan
	required := append([]string{permAIQuery, permFlowRead}, flow.QueryPlanPermissions(plan)...)
	page, err := s.flowSnapshots.Create(ctx, scope, required, plan.PageSize, s.flowSnapshotAuthorizer(p), func(ctx context.Context) (flowsnapshot.Input, error) {
		result, err := s.recordFlowSpec(ctx, p.TenantID, plan, nil)
		if err != nil {
			return flowsnapshot.Input{}, err
		}
		result.SavedFilterVersions = versions
		proof, until, err := s.flowSnapshotSource.receipt(ctx, scope, result)
		if err != nil {
			return flowsnapshot.Input{}, err
		}
		details := make([]json.RawMessage, len(result.Rows))
		for i, row := range result.Rows {
			details[i], err = json.Marshal(row)
			if err != nil {
				return flowsnapshot.Input{}, apierror.Unavailable("flow result encoding unavailable")
			}
		}
		legacyRows := flowExplorerRows(result.Rows, query)
		common := explorerResult{Query: query, Preview: ai.ExplorerPreview(query), Columns: explorerColumns(query), Suggestions: explorerSuggestions(legacyRows, query.Dimensions), EvidencePath: "/planes/flow", Execution: flowExplorerReceipt(query, result, time.Since(started)), Flow: &result}
		common.Flow.Rows = nil
		header, err := json.Marshal(common)
		if err != nil {
			return flowsnapshot.Input{}, apierror.Unavailable("flow result metadata encoding unavailable")
		}
		frozenQuery, err := json.Marshal(query)
		if err != nil {
			return flowsnapshot.Input{}, apierror.Unavailable("flow query encoding unavailable")
		}
		return flowsnapshot.Input{Query: frozenQuery, Header: header, Validity: proof, Rows: details, ValidUntil: until}, nil
	})
	if err != nil {
		return explorerResult{}, flowSnapshotError(err)
	}
	return decodeFlowSnapshotPage(page)
}

func (s *Server) handleResumeFlowSnapshot(w http.ResponseWriter, r *http.Request, p *auth.Principal, query ai.ExplorerQuery) error {
	result, err := s.resumeFlowSnapshot(r.Context(), p, query)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) resumeFlowSnapshot(ctx context.Context, p *auth.Principal, query ai.ExplorerQuery) (_ explorerResult, operationErr error) {
	finish := s.beginFlowOperation(ctx, "page")
	defer func() { finish(operationErr) }()
	if s.flowSnapshots == nil {
		return explorerResult{}, apierror.Unavailable("shared flow snapshot storage is unavailable")
	}
	// A continuation has exactly the source and opaque cursor. Reject all
	// overrides, including a new question/window/filter that could make the
	// displayed result silently mean something different.
	if query.Source != ai.ExplorerFlow || query.Flow == nil {
		return explorerResult{}, apierror.Validation("flow continuation requires the flow source")
	}
	cursor := query.Flow.Cursor
	if err := validateFlowContinuation(query); err != nil {
		return explorerResult{}, err
	}
	scope, err := flowSnapshotScope(p)
	if err != nil {
		return explorerResult{}, err
	}
	page, err := s.flowSnapshots.Resume(ctx, scope, cursor, s.flowSnapshotAuthorizer(p))
	if err != nil {
		return explorerResult{}, flowSnapshotError(err)
	}
	return decodeFlowSnapshotPage(page)
}

func validateFlowContinuation(query ai.ExplorerQuery) error {
	if query.Source != ai.ExplorerFlow || query.Flow == nil || strings.TrimSpace(query.Flow.Cursor) == "" {
		return apierror.Validation("flow continuation requires the flow source and cursor")
	}
	plan := *query.Flow
	plan.Cursor = ""
	remainder := query
	remainder.Source = ""
	remainder.Flow = nil
	if !reflect.DeepEqual(plan, flow.QueryPlan{}) || !reflect.DeepEqual(remainder, ai.ExplorerQuery{}) {
		return apierror.Validation("a flow continuation accepts only source and flow.cursor")
	}
	return nil
}

// decodeFlowSnapshotPage projects an already-authorized private snapshot page.
// The HTTP writer consumes this typed result. Additional transports must
// authorize in the source service before loading the page.
func decodeFlowSnapshotPage(page flowsnapshot.Page) (explorerResult, error) {
	var kind struct {
		ContractVersion string `json:"contract_version"`
	}
	if err := json.Unmarshal(page.Data, &kind); err != nil {
		return explorerResult{}, apierror.Unavailable("flow snapshot metadata is invalid")
	}
	if kind.ContractVersion != "" {
		return explorerResult{}, apierror.Validation("this cursor belongs to a flow comparison")
	}
	var result explorerResult
	if err := json.Unmarshal(page.Data, &result); err != nil || result.Flow == nil {
		return explorerResult{}, apierror.Unavailable("flow snapshot metadata is invalid")
	}
	if err := json.Unmarshal(page.Query, &result.Query); err != nil || result.Query.Source != ai.ExplorerFlow {
		return explorerResult{}, apierror.Unavailable("flow snapshot query is invalid")
	}
	result.Flow.Rows = make([]flowstore.PlanRow, len(page.Rows))
	for i, row := range page.Rows {
		if err := json.Unmarshal(row, &result.Flow.Rows[i]); err != nil {
			return explorerResult{}, apierror.Unavailable("flow snapshot row is invalid")
		}
	}
	result.Rows = flowExplorerRows(result.Flow.Rows, result.Query)
	if result.Flow.Other != nil {
		result.Rows = append(result.Rows, flowExplorerRows([]flowstore.PlanRow{*result.Flow.Other}, result.Query)...)
	}
	result.Execution.ReturnedRows = len(result.Rows)
	result.FlowPaging = &flowSnapshotPaging{SnapshotID: page.SnapshotID, ExpiresAt: page.ExpiresAt, SelectedRows: page.SelectedRows, Offset: page.Offset, PageSize: page.PageSize, More: page.NextCursor != "", NextCursor: page.NextCursor}
	return result, nil
}
