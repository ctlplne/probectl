// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

// A snapshot row is one selected group, independent of the metric count.
// A missing period is explicit, never fabricated as a measured zero.
type flowComparisonSnapshotRow struct {
	Current  *flowstore.PlanRow `json:"current"`
	Previous *flowstore.PlanRow `json:"previous"`
}

func packFlowComparisonRows(current, previous []flowstore.PlanRow, plan flow.QueryPlan, budgets ...flowstore.ExplorerBudget) ([]json.RawMessage, error) {
	budget, err := flowComparisonCostBudget(budgets)
	if err != nil {
		return nil, err
	}
	var charged int64
	selected, err := selectFlowComparisonGroups(current, previous, plan)
	if err != nil {
		return nil, err
	}
	byKey := map[string]*flowComparisonSnapshotRow{}
	add := func(rows []flowstore.PlanRow, current bool) {
		for _, row := range rows {
			key := flowComparisonKey(row, plan.GroupBy)
			if byKey[key] == nil {
				byKey[key] = &flowComparisonSnapshotRow{}
			}
			entry := row
			if current {
				byKey[key].Current = &entry
			} else {
				byKey[key].Previous = &entry
			}
		}
	}
	add(current, true)
	add(previous, false)
	result := make([]json.RawMessage, 0, len(selected))
	for _, tuple := range selected {
		group := map[string]string{}
		for i, name := range plan.GroupBy {
			group[name] = tuple[i]
		}
		row := byKey[flowComparisonKey(flowstore.PlanRow{Group: group}, plan.GroupBy)]
		if row == nil {
			return nil, flowsnapshot.ErrIntegrity
		}
		encoded, err := json.Marshal(row)
		if err != nil {
			return nil, err
		}
		if int64(len(encoded)) > min(budget.ReadBytes, budget.MemoryBytes)-charged {
			return nil, flowstore.ErrExplorerBudget
		}
		charged += int64(len(encoded))
		result = append(result, encoded)
	}
	return result, nil
}

func (s *Server) createFlowComparisonSnapshot(ctx context.Context, p *auth.Principal, current, previous ai.ExplorerQuery, versions map[string]int64) (explorerComparisonResult, error) {
	ctx = auth.WithPrincipal(ctx, p)
	scope, err := flowSnapshotScope(p)
	if err != nil {
		return explorerComparisonResult{}, err
	}
	if s.flowSnapshotSource == nil {
		return explorerComparisonResult{}, apierror.Unavailable("flow snapshot source validation is unavailable")
	}
	if s.flowSnapshots == nil {
		return explorerComparisonResult{}, apierror.Unavailable("shared flow snapshot storage is unavailable")
	}
	metadataPermissions, err := flowPlanPermissions(ctx, p.TenantID, *current.Flow)
	if err != nil {
		return explorerComparisonResult{}, err
	}
	required := append([]string{permAIQuery, permFlowRead}, metadataPermissions...)
	page, err := s.flowSnapshots.Create(ctx, scope, required, current.Flow.PageSize, s.flowSnapshotAuthorizer(p), func(ctx context.Context) (flowsnapshot.Input, error) {
		common, err := s.collectFlowComparison(ctx, p, current, previous, versions)
		if err != nil {
			return flowsnapshot.Input{}, err
		}
		proof, until, err := s.flowSnapshotSource.receipt(ctx, scope, common.Flow.Current, common.Flow.Previous)
		if err != nil {
			return flowsnapshot.Input{}, err
		}
		details, err := packFlowComparisonRows(common.Flow.Current.Rows, common.Flow.Previous.Rows, *current.Flow, flowstore.ExplorerQueryBudget(s.flowStore))
		if err != nil {
			return flowsnapshot.Input{}, flowSnapshotError(err)
		}
		common.Flow.Current.Rows = nil
		common.Flow.Previous.Rows = nil
		metadata, err := json.Marshal(common)
		if err != nil {
			return flowsnapshot.Input{}, err
		}
		query, err := json.Marshal(explorerComparisonRequest{Query: current, PreviousFrom: previous.From, PreviousTo: previous.To})
		if err != nil {
			return flowsnapshot.Input{}, err
		}
		return flowsnapshot.Input{Query: query, Header: metadata, Validity: proof, Rows: details, ValidUntil: until}, nil
	})
	if err != nil {
		return explorerComparisonResult{}, flowSnapshotError(err)
	}
	return decodeFlowComparisonSnapshotPage(page, flowstore.ExplorerQueryBudget(s.flowStore))
}

func (s *Server) handleResumeFlowComparisonSnapshot(w http.ResponseWriter, r *http.Request, p *auth.Principal, query ai.ExplorerQuery) error {
	result, err := s.resumeFlowComparisonSnapshot(r.Context(), p, query)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) resumeFlowComparisonSnapshot(ctx context.Context, p *auth.Principal, query ai.ExplorerQuery) (_ explorerComparisonResult, operationErr error) {
	ctx = auth.WithPrincipal(ctx, p)
	finish := s.beginFlowOperation(ctx, "comparison_page")
	defer func() { finish(operationErr) }()
	if err := validateFlowContinuation(query); err != nil {
		return explorerComparisonResult{}, err
	}
	if s.flowSnapshots == nil {
		return explorerComparisonResult{}, apierror.Unavailable("shared flow snapshot storage is unavailable")
	}
	scope, err := flowSnapshotScope(p)
	if err != nil {
		return explorerComparisonResult{}, err
	}
	page, err := s.flowSnapshots.Resume(ctx, scope, query.Flow.Cursor, s.flowSnapshotAuthorizer(p))
	if err != nil {
		return explorerComparisonResult{}, flowSnapshotError(err)
	}
	return decodeFlowComparisonSnapshotPage(page, flowstore.ExplorerQueryBudget(s.flowStore))
}

func flowComparisonSnapshotMetadata(data json.RawMessage) (explorerComparisonResult, error) {
	var result explorerComparisonResult
	if err := json.Unmarshal(data, &result); err != nil || result.ContractVersion != "flow-explorer-comparison/v2" || result.Flow == nil || result.Current.Flow == nil || result.Previous.Flow == nil {
		return explorerComparisonResult{}, apierror.Validation("this cursor does not belong to a flow comparison")
	}
	return result, nil
}

func decodeFlowComparisonSnapshotRow(raw json.RawMessage) (flowComparisonSnapshotRow, error) {
	var row flowComparisonSnapshotRow
	if err := json.Unmarshal(raw, &row); err != nil || row.Current == nil && row.Previous == nil || row.Current != nil && row.Current.Other || row.Previous != nil && row.Previous.Other {
		return row, flowsnapshot.ErrIntegrity
	}
	return row, nil
}

// decodeFlowComparisonSnapshotPage preserves exact values and missing periods
// at the shared typed transport boundary after the private source read.
func decodeFlowComparisonSnapshotPage(page flowsnapshot.Page, budgets ...flowstore.ExplorerBudget) (explorerComparisonResult, error) {
	result, err := flowComparisonSnapshotMetadata(page.Data)
	if err != nil {
		return explorerComparisonResult{}, err
	}
	result.Flow.Current.Rows = []flowstore.PlanRow{}
	result.Flow.Previous.Rows = []flowstore.PlanRow{}
	for _, raw := range page.Rows {
		row, err := decodeFlowComparisonSnapshotRow(raw)
		if err != nil {
			return explorerComparisonResult{}, flowSnapshotError(err)
		}
		if row.Current != nil {
			result.Flow.Current.Rows = append(result.Flow.Current.Rows, *row.Current)
		}
		if row.Previous != nil {
			result.Flow.Previous.Rows = append(result.Flow.Previous.Rows, *row.Previous)
		}
	}
	result.Rows, err = alignExactFlowComparison(flowComparisonRows(result.Flow.Current), flowComparisonRows(result.Flow.Previous), result.Groupings, result.Current.Measures, result.Current.Flow.RowLimit, budgets...)
	if err != nil {
		return explorerComparisonResult{}, err
	}
	result.Execution.Alignment.ReturnedRows = len(result.Rows)
	result.FlowPaging = &flowSnapshotPaging{SnapshotID: page.SnapshotID, ExpiresAt: page.ExpiresAt, SelectedRows: page.SelectedRows, Offset: page.Offset, PageSize: page.PageSize, More: page.NextCursor != "", NextCursor: page.NextCursor}
	return result, nil
}
