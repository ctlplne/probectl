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
	"math/big"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type flowExplorerComparisonData struct {
	Current    flowstore.PlanResult `json:"current"`
	Previous   flowstore.PlanResult `json:"previous"`
	Membership string               `json:"membership"`
}

func (s *Server) handleRecordFlowComparison(w http.ResponseWriter, r *http.Request, principal *auth.Principal, current, previous ai.ExplorerQuery) error {
	result, err := s.recordFlowComparison(r.Context(), principal, current, previous)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) recordFlowComparison(ctx context.Context, principal *auth.Principal, current, previous ai.ExplorerQuery) (_ explorerComparisonResult, operationErr error) {
	finish := s.beginFlowOperation(ctx, "comparison")
	defer func() { finish(operationErr) }()
	if err := s.authorizeNativeFlow(ctx, principal); err != nil {
		return explorerComparisonResult{}, err
	}
	if previous.Source != ai.ExplorerFlow {
		return explorerComparisonResult{}, apierror.Validation("flow comparison requires the flow source in both periods")
	}
	plan, versions, err := s.resolveFlowSpec(ctx, principal.TenantID, current)
	if err != nil {
		return explorerComparisonResult{}, err
	}
	if err := s.authorizeFlowMetadata(ctx, principal, plan); err != nil {
		return explorerComparisonResult{}, err
	}
	if flowstore.PlanUsesInterfaceRoles(plan) {
		ctx, err = bindFlowRoleContext(ctx, principal)
		if err != nil {
			return explorerComparisonResult{}, err
		}
	}
	current.Flow = &plan
	previousPlan := plan
	previousPlan.From, previousPlan.To = previous.From, previous.To
	tagData, err := flowTagQueryFromContext(ctx, principal.TenantID)
	if err != nil {
		return explorerComparisonResult{}, err
	}
	if tagData == nil {
		previousPlan, err = flow.NormalizeQueryPlan(previousPlan, time.Now())
	} else {
		vocabulary, vocabErr := tagData.Vocabulary(principal.TenantID)
		if vocabErr != nil {
			return explorerComparisonResult{}, apierror.Unavailable("tenant tag query scope is unavailable")
		}
		previousPlan, err = flow.NormalizeQueryPlanWithVocabulary(previousPlan, time.Now(), vocabulary)
	}
	if err != nil {
		return explorerComparisonResult{}, apierror.Validation(err.Error())
	}
	previous.Flow = &previousPlan
	if s.flowSnapshots != nil {
		return s.createFlowComparisonSnapshot(ctx, principal, current, previous, versions)
	}
	result, err := s.collectFlowComparison(ctx, principal, current, previous, versions)
	if err != nil {
		return explorerComparisonResult{}, err
	}
	groups, err := packFlowComparisonRows(result.Flow.Current.Rows, result.Flow.Previous.Rows, plan, flowstore.ExplorerQueryBudget(s.flowStore))
	if err != nil {
		return explorerComparisonResult{}, flowSnapshotError(err)
	}
	if len(groups) > plan.PageSize {
		return explorerComparisonResult{}, apierror.Unavailable("shared flow snapshot storage is required for comparison paging")
	}
	result.Rows, err = alignExactFlowComparison(flowComparisonRows(result.Flow.Current), flowComparisonRows(result.Flow.Previous), current.Groupings, current.Measures, plan.RowLimit, flowstore.ExplorerQueryBudget(s.flowStore))
	if err != nil {
		return explorerComparisonResult{}, err
	}
	result.Execution.Alignment.ReturnedRows = len(result.Rows)
	return result, nil
}

// The caller holds a shared snapshot lease across every source pass when a
// result is persisted. Both periods use the same detail/chart/matrix axes.
func (s *Server) collectFlowComparison(ctx context.Context, principal *auth.Principal, current, previous ai.ExplorerQuery, versions map[string]int64) (explorerComparisonResult, error) {
	started := time.Now()
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return explorerComparisonResult{}, apierror.Unavailable("flow cost policy unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 6*budget.ExecutionLimit)
	defer cancel()
	currentSpec, previousSpec := *current.Flow, *previous.Flow
	var currentDuration, previousDuration time.Duration
	roleDigest := ""
	queryWindow := func(plan flow.QueryPlan, groups, columns, chart, matrixRows [][]string, elapsed *time.Duration) (flowstore.PlanResult, error) {
		began := time.Now()
		data, err := s.recordFlowSpec(ctx, principal.TenantID, plan, groups, columns, chart, matrixRows)
		*elapsed += time.Since(began)
		data.SavedFilterVersions = versions
		if err == nil && flowstore.PlanUsesInterfaceRoles(plan) {
			if data.RoleDigest == "" || roleDigest != "" && roleDigest != data.RoleDigest {
				return flowstore.PlanResult{}, apierror.Unavailable("interface role inputs changed between source passes; run a fresh comparison")
			}
			roleDigest = data.RoleDigest
		}
		return data, err
	}
	currentData, err := queryWindow(currentSpec, nil, nil, nil, nil, &currentDuration)
	if err != nil {
		return explorerComparisonResult{}, err
	}
	previousData, err := queryWindow(previousSpec, nil, nil, nil, nil, &previousDuration)
	if err != nil {
		return explorerComparisonResult{}, err
	}
	selected, err := selectFlowComparisonGroups(currentData.Rows, previousData.Rows, currentSpec)
	if err != nil {
		return explorerComparisonResult{}, err
	}
	var chartGroups, matrixRows [][]string
	if currentSpec.View != "table" && currentSpec.View != "matrix" {
		axis := currentSpec
		axis.RowLimit = currentSpec.SeriesDepth
		chartGroups, err = selectFlowComparisonGroups(currentData.ChartRows, previousData.ChartRows, axis)
		if err != nil {
			return explorerComparisonResult{}, err
		}
	}
	if currentSpec.View == "matrix" {
		axis := currentSpec
		axis.RowLimit = currentSpec.MatrixDepth
		matrixRows, err = selectFlowComparisonGroups(currentData.MatrixRows, previousData.MatrixRows, axis)
		if err != nil {
			return explorerComparisonResult{}, err
		}
	}
	currentData, err = queryWindow(currentSpec, selected, nil, chartGroups, matrixRows, &currentDuration)
	if err != nil {
		return explorerComparisonResult{}, err
	}
	previousData, err = queryWindow(previousSpec, selected, nil, chartGroups, matrixRows, &previousDuration)
	if err != nil {
		return explorerComparisonResult{}, err
	}
	if currentSpec.View == "matrix" {
		axis := currentSpec
		axis.GroupBy, axis.RowLimit = currentSpec.MatrixWith, currentSpec.MatrixDepth
		columns, err := selectFlowComparisonGroups(currentData.MatrixColumns, previousData.MatrixColumns, axis)
		if err != nil {
			return explorerComparisonResult{}, err
		}
		currentData, err = queryWindow(currentSpec, selected, columns, chartGroups, matrixRows, &currentDuration)
		if err != nil {
			return explorerComparisonResult{}, err
		}
		previousData, err = queryWindow(previousSpec, selected, columns, chartGroups, matrixRows, &previousDuration)
		if err != nil {
			return explorerComparisonResult{}, err
		}
	}
	// Suggestions are bounded presentation metadata, not a second copy of
	// the entire selected50k population expanded across every metric.
	currentRows := flowExplorerRows(currentData.Rows[:min(len(currentData.Rows), 100)], current)
	previousRows := flowExplorerRows(previousData.Rows[:min(len(previousData.Rows), 100)], previous)
	return explorerComparisonResult{ContractVersion: "flow-explorer-comparison/v2", Current: current, Previous: previous, CurrentPreview: ai.ExplorerPreview(current), PreviousPreview: ai.ExplorerPreview(previous), Groupings: current.Groupings, Suggestions: explorerSuggestions(append(currentRows, previousRows...), current.Dimensions), EvidencePath: "/planes/flow", State: explorerComparisonState(currentData.TotalGroups > 0, previousData.TotalGroups > 0), Flow: &flowExplorerComparisonData{Current: currentData, Previous: previousData, Membership: "shared_top_groups_ranked_by_larger_period_value"}, Execution: explorerComparisonExecutionReceipt{ContractVersion: "flow-explorer-comparison-execution/v2", TenantScoped: true, Current: flowExplorerReceipt(current, currentData, currentDuration), Previous: flowExplorerReceipt(previous, previousData, previousDuration), Alignment: explorerAlignmentExecutionReceipt{RowLimit: currentSpec.RowLimit, TruncationReason: "none"}, TotalMS: time.Since(started).Milliseconds()}}, nil
}

func flowComparisonKey(row flowstore.PlanRow, fields []string) string {
	tuple := make([]string, len(fields))
	for i, name := range fields {
		tuple[i] = row.Group[name]
	}
	encoded, _ := json.Marshal(struct {
		Other bool
		Tuple []string
	}{row.Other, tuple})
	return string(encoded)
}

func alignExactFlowComparison(current, previous []flowstore.PlanRow, fields, measures []string, limit int, budgets ...flowstore.ExplorerBudget) ([]explorerComparisonRow, error) {
	budget, err := flowComparisonCostBudget(budgets)
	if err != nil {
		return nil, err
	}
	currentByKey := map[string]flowstore.PlanRow{}
	previousByKey := map[string]flowstore.PlanRow{}
	keys := map[string]bool{}
	for _, row := range current {
		key := flowComparisonKey(row, fields)
		currentByKey[key] = row
		keys[key] = true
	}
	for _, row := range previous {
		key := flowComparisonKey(row, fields)
		previousByKey[key] = row
		keys[key] = true
	}
	// Bound actual response allocation, independently of public group/metric
	// reach. Each cell owns several exact-decimal strings and scalar pointers.
	cellBytes := int(reflect.TypeFor[explorerComparisonRow]().Size()) + 128
	if len(measures) > 0 && int64(len(keys)) > min(budget.ReadBytes, budget.MemoryBytes)/int64(cellBytes)/int64(len(measures)) {
		return nil, apierror.Validation("flow comparison response exceeds its memory budget; page or select fewer metrics").WithCode(string(apierror.CodeFlowQueryBudget))
	}
	detailGroups := 0
	for _, row := range currentByKey {
		if !row.Other {
			detailGroups++
		}
	}
	for key, row := range previousByKey {
		if !row.Other {
			if _, found := currentByKey[key]; !found {
				detailGroups++
			}
		}
	}
	if detailGroups > limit {
		return nil, apierror.Validation("comparison selected group count exceeds its row limit")
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	result := []explorerComparisonRow{}
	for _, key := range ordered {
		now, hasNow := currentByKey[key]
		before, hasBefore := previousByKey[key]
		group := now.Group
		other := now.Other
		if !hasNow {
			group = before.Group
			other = before.Other
		}
		for _, measure := range measures {
			row := explorerComparisonRow{Group: group, Other: other, Measure: measure, Aggregation: "sum", DeltaState: "comparable"}
			if _, calculation, found := strings.Cut(measure, ":"); found {
				row.Aggregation = calculation
			}
			switch measure {
			case "bps", "pps":
				row.Aggregation = "mean"
			case "unique_src", "unique_dst":
				row.Aggregation = "exact_distinct"
			}
			n, p := new(big.Rat), new(big.Rat)
			if hasNow {
				value := now.Metrics[measure]
				if _, ok := n.SetString(value); !ok {
					return nil, apierror.Unavailable("invalid current flow measure")
				}
				row.CurrentExact = &value
				v, _ := n.Float64()
				row.CurrentValue = &v
			}
			if hasBefore {
				value := before.Metrics[measure]
				if _, ok := p.SetString(value); !ok {
					return nil, apierror.Unavailable("invalid previous flow measure")
				}
				row.PreviousExact = &value
				v, _ := p.Float64()
				row.PreviousValue = &v
			}
			switch {
			case !hasNow:
				row.DeltaState = "missing_current"
			case !hasBefore:
				row.DeltaState = "missing_previous"
			default:
				delta := new(big.Rat).Sub(n, p)
				text := delta.Num().String()
				if !delta.IsInt() {
					text = delta.FloatString(18)
				}
				row.DeltaExact = &text
				v, _ := delta.Float64()
				row.Delta = &v
				if p.Sign() == 0 {
					row.DeltaState = "zero_baseline"
				} else {
					percent := new(big.Rat).Mul(new(big.Rat).Quo(delta, p), big.NewRat(100, 1))
					text := percent.FloatString(9)
					row.PercentExact = &text
					v, _ := percent.Float64()
					row.PercentChange = &v
				}
			}
			result = append(result, row)
		}
	}
	return result, nil
}

// Keep one exact population across periods, including the Other complement.
// Rank the union by the larger primary value in either period, then preserve
// that same order for both stores' detail/chart membership.
func selectFlowComparisonGroups(current, previous []flowstore.PlanRow, plan flow.QueryPlan) ([][]string, error) {
	primary := ""
	for _, metric := range plan.Metrics {
		if metric.Role == "primary" {
			primary = metric.Measure + ":" + metric.Calculation
		}
	}
	type candidate struct {
		tuple []string
		value *big.Rat
	}
	groups := map[string]candidate{}
	for _, row := range append(append([]flowstore.PlanRow{}, current...), previous...) {
		tuple := make([]string, len(plan.GroupBy))
		for i, field := range plan.GroupBy {
			tuple[i] = row.Group[field]
		}
		encoded, _ := json.Marshal(tuple)
		key := string(encoded)
		value, ok := new(big.Rat).SetString(row.Metrics[primary])
		if !ok {
			return nil, errors.New("invalid comparison rank value")
		}
		if existing, ok := groups[key]; !ok || value.Cmp(existing.value) > 0 {
			groups[key] = candidate{tuple: tuple, value: value}
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if cmp := groups[keys[i]].value.Cmp(groups[keys[j]].value); cmp != 0 {
			return cmp > 0
		}
		return keys[i] < keys[j]
	})
	selected := [][]string{}
	for _, key := range keys[:min(len(keys), plan.RowLimit)] {
		selected = append(selected, groups[key].tuple)
	}
	return selected, nil
}

func flowComparisonRows(result flowstore.PlanResult) []flowstore.PlanRow {
	rows := make([]flowstore.PlanRow, 0, len(result.Rows)+1)
	for _, row := range result.Rows {
		rows = append(rows, flowstore.PlanRow{Group: row.Group, Other: row.Other, Metrics: row.Metrics})
	}
	if result.Other != nil {
		rows = append(rows, flowstore.PlanRow{Group: result.Other.Group, Other: true, Metrics: result.Other.Metrics})
	}
	return rows
}

func flowComparisonCostBudget(budgets []flowstore.ExplorerBudget) (flowstore.ExplorerBudget, error) {
	budget := flowstore.DefaultExplorerBudget()
	if len(budgets) > 1 {
		return flowstore.ExplorerBudget{}, apierror.Unavailable("flow cost policy unavailable")
	}
	if len(budgets) == 1 {
		budget = budgets[0]
	}
	if budget.Validate() != nil {
		return flowstore.ExplorerBudget{}, apierror.Unavailable("flow cost policy unavailable")
	}
	return budget, nil
}
