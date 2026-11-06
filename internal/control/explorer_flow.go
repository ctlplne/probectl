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
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/chclient"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
)

func flowExplorerSchema(budgets ...flowstore.ExplorerBudget) map[string]any {
	budget := flowstore.DefaultExplorerBudget()
	if len(budgets) == 1 {
		budget = budgets[0]
	}
	return map[string]any{
		"contract_version": "flow-explorer/v2", "fields": flow.QueryFields(), "metrics": flow.QueryMetricDefinitions(),
		"render_cost": mcp.DefaultNativeFlowRenderBudget(),
		"limits":      map[string]any{"max_groups": flow.MaxPlanDimensions, "max_matrix_dimensions": flow.MaxPlanMatrixDimensions, "max_matrix_depth": flow.MaxPlanMatrixDepth, "max_chart_series": flow.MaxPlanChartSeries, "max_chart_rows": flow.MaxPlanChartRows, "max_table_rows": flow.MaxPlanTableRows, "max_page_rows": flow.MaxPlanPageRows, "min_bucket_seconds": flow.MinPlanBucketSeconds, "max_bucket_seconds": flow.MaxPlanBucketSeconds, "max_group_entries": flow.MaxQueryGroupEntries, "max_expanded_conditions": flow.MaxQueryPredicates, "max_filter_depth": flow.MaxQueryFilterDepth, "max_regex_bytes": flow.MaxQueryRegexBytes, "max_values_per_predicate": flow.MaxQueryValues, "max_value_bytes": flow.MaxQueryValueBytes, "max_tag_value_characters": tags.MaxValueCharacters, "max_tag_value_bytes": tags.MaxValueBytes, "grammar_bytes": flow.MaxPlanGrammarBytes, "execution_seconds": budget.ExecutionLimit.Seconds(), "read_bytes": budget.ReadBytes, "read_rows": budget.ReadRows, "response_bytes": budget.ResponseBytes, "memory_bytes": budget.MemoryBytes, "intermediate_groups": budget.IntermediateGroups, "interface_items": budget.InterfaceItems, "threads": budget.Threads},
		"defaults":    map[string]any{"ipv4_prefix_length": 24, "ipv6_prefix_length": 48, "bucket_seconds": 60, "series_depth": 40, "row_limit": 100},
		"time_range":  "tenant retention and source coverage; no fixed day cap",
		"statistics":  map[string]any{"percentile": "nearest rank, including idle zero buckets", "rate_average": "duration weighted", "decimal_places": 18, "decimal_rounding": "toward zero", "distinct_total": "whole-window exact identities", "distinct_bucket_total": "sum of per-bucket distinct counts"},
	}
}

func (s *Server) authorizeFlowMetadata(ctx context.Context, principal *auth.Principal, plan flow.QueryPlan) error {
	permissions, err := flowPlanPermissions(ctx, principal.TenantID, plan)
	if err != nil {
		return err
	}
	for _, permission := range permissions {
		decision, err := s.decide(ctx, principal, permission, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: principal.TenantID})
		if err != nil {
			return err
		}
		if decision != auth.DecisionAllowed {
			return apierror.Forbidden("selected flow metadata requires " + permission)
		}
	}
	return nil
}

func flowPlanPermissions(ctx context.Context, tenant string, plan flow.QueryPlan) ([]string, error) {
	data, err := flowTagQueryFromContext(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if data == nil {
		vocabulary, bound, err := flow.QueryVocabularyFromContext(ctx, tenant)
		if err != nil {
			return nil, apierror.Unavailable("tenant tag query scope is unavailable")
		}
		if bound {
			return flow.QueryPlanPermissionsWithVocabulary(plan, vocabulary), nil
		}
		return flow.QueryPlanPermissions(plan), nil
	}
	vocabulary, err := data.Vocabulary(tenant)
	if err != nil {
		return nil, apierror.Unavailable("tenant tag query scope is unavailable")
	}
	return flow.QueryPlanPermissionsWithVocabulary(plan, vocabulary), nil
}

// resolveFlowSpec reads reusable configuration inside the authenticated tenant
// before inspecting joined-data permissions. A reference cannot hide a field.
func (s *Server) resolveFlowSpec(ctx context.Context, tenant string, query ai.ExplorerQuery) (flow.QueryPlan, map[string]int64, error) {
	data, err := flowTagQueryFromContext(ctx, tenant)
	if err != nil {
		return flow.QueryPlan{}, nil, err
	}
	var vocabulary flow.QueryVocabulary
	if data != nil {
		vocabulary, err = data.Vocabulary(tenant)
		if err != nil {
			return flow.QueryPlan{}, nil, apierror.Unavailable("tenant tag query scope is unavailable")
		}
	}
	var plan flow.QueryPlan
	if data == nil {
		plan, err = ai.ExplorerFlowSpec(query, time.Now())
	} else {
		plan, err = ai.ExplorerFlowSpecWithVocabulary(query, time.Now(), vocabulary)
	}
	if err != nil {
		return flow.QueryPlan{}, nil, apierror.Validation(err.Error())
	}
	var resolved flow.ResolvedQueryFilters
	if data == nil {
		resolved, err = flow.ResolveQueryFilters(ctx, tenant, plan.Filter, s.flowQueryFilters, "")
	} else {
		resolved, err = flow.ResolveQueryFiltersWithVocabulary(ctx, tenant, plan.Filter, s.flowQueryFilters, "", vocabulary)
	}
	if err != nil {
		if errors.Is(err, flow.ErrQueryFilterNotFound) {
			return flow.QueryPlan{}, nil, apierror.NotFound("saved flow filter not found")
		}
		return flow.QueryPlan{}, nil, apierror.Validation("saved flow filters could not be resolved within the query bounds")
	}
	plan.Filter = resolved.Expression
	if data == nil {
		plan, err = flow.NormalizeQueryPlan(plan, time.Now())
	} else {
		plan, err = flow.NormalizeQueryPlanWithVocabulary(plan, time.Now(), vocabulary)
	}
	if err != nil {
		return flow.QueryPlan{}, nil, apierror.Validation(err.Error())
	}
	return plan, resolved.Versions, nil
}

func flowExplorerStoreError(err error) error {
	if errors.Is(err, flowstore.ErrSnapshotInputs) {
		return apierror.Validation("flow snapshot inputs are no longer available; run a fresh query").WithCode(string(apierror.CodeFlowQueryCoverage))
	}
	var coverage *flowstore.PlanCoverageError
	if errors.As(err, &coverage) {
		return apierror.Validation(coverage.Error()).WithCode(string(apierror.CodeFlowQueryCoverage))
	}
	if errors.Is(err, flowstore.ErrExplorerBudget) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, chclient.ErrResponseTooLarge) {
		return apierror.Validation("flow query resource budget exceeded; narrow the time window, filters, or grouping").WithCode(string(apierror.CodeFlowQueryBudget))
	}
	return apierror.Unavailable("flow record query is temporarily unavailable")
}

func (s *Server) recordFlowSpec(ctx context.Context, tenant string, plan flow.QueryPlan, selected [][]string, membership ...[][]string) (flowstore.PlanResult, error) {
	tagData, err := flowTagQueryFromContext(ctx, tenant)
	if err != nil {
		return flowstore.PlanResult{}, err
	}
	backend, ok := flowstore.PlanStoreOf(s.flowStore)
	if !ok {
		return flowstore.PlanResult{}, apierror.Unavailable("flow record queries are unavailable from the configured store")
	}
	if len(membership) > 3 {
		return flowstore.PlanResult{}, apierror.Validation("invalid matrix column selection")
	}
	var selectedColumns, selectedChart, selectedMatrixRows [][]string
	if len(membership) >= 1 {
		selectedColumns = membership[0]
	}
	if len(membership) >= 2 {
		selectedChart = membership[1]
	}
	if len(membership) >= 3 {
		selectedMatrixRows = membership[2]
	}
	query := flowstore.PlanQuery{TenantID: tenant, Plan: plan, Tags: tagData, SelectedGroups: selected, SelectedColumns: selectedColumns, SelectedChartGroups: selectedChart, SelectedMatrixRows: selectedMatrixRows}
	var roleBefore flowRoleSnapshot
	if flowstore.PlanUsesInterfaceRoles(plan) {
		roleBefore, err = s.loadFlowRoleSnapshot(ctx, auth.PrincipalFrom(ctx), flowstore.ExplorerOperationBudget(ctx, s.flowStore))
		if err != nil {
			return flowstore.PlanResult{}, err
		}
		query.Roles = roleBefore.data
	}
	var result flowstore.PlanResult
	if batch, ok := ctx.Value(reportFlowBatchKey{}).(*flowstore.PlanBatch); ok {
		if batch == nil {
			return flowstore.PlanResult{}, apierror.Unavailable("report source batch is unavailable")
		}
		result, err = batch.ExplorePlan(query)
	} else {
		result, err = backend.ExplorePlan(ctx, query)
	}
	if err != nil {
		return flowstore.PlanResult{}, flowExplorerStoreError(err)
	}
	if flowstore.PlanUsesInterfaceRoles(plan) {
		after, err := s.loadFlowRoleSnapshot(ctx, auth.PrincipalFrom(ctx), flowstore.ExplorerOperationBudget(ctx, s.flowStore))
		if err != nil {
			return flowstore.PlanResult{}, err
		}
		digest, err := after.data.Digest(ctx, tenant, time.Now().UTC())
		if err != nil || roleBefore.inputDigest != after.inputDigest || result.RoleDigest != digest || result.RoleTenantID != tenant {
			return flowstore.PlanResult{}, apierror.Unavailable("interface role inputs changed; run a fresh query")
		}
	}
	return result, nil
}

func (s *Server) authorizeNativeFlow(ctx context.Context, principal *auth.Principal) error {
	if principal == nil || strings.TrimSpace(principal.TenantID) == "" {
		return apierror.Unauthorized("tenant identity required for native flow queries")
	}
	for _, permission := range []string{permAIQuery, permFlowRead} {
		if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: principal.TenantID}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleRecordFlowQuery(w http.ResponseWriter, r *http.Request, principal *auth.Principal, query ai.ExplorerQuery) error {
	result, err := s.recordFlowQuery(r.Context(), principal, query)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

// recordFlowQuery shares native execution without a synthetic HTTP request.
// The transport owns fairness admission; the service rechecks tenant/source grants.
func (s *Server) recordFlowQuery(ctx context.Context, principal *auth.Principal, query ai.ExplorerQuery) (_ explorerResult, operationErr error) {
	finish := s.beginFlowOperation(ctx, "query")
	defer func() { finish(operationErr) }()
	if err := s.authorizeNativeFlow(ctx, principal); err != nil {
		return explorerResult{}, err
	}
	plan, versions, err := s.resolveFlowSpec(ctx, principal.TenantID, query)
	if err != nil {
		return explorerResult{}, err
	}
	if err := s.authorizeFlowMetadata(ctx, principal, plan); err != nil {
		return explorerResult{}, err
	}
	if s.flowSnapshots != nil {
		return s.createFlowSnapshot(ctx, principal, query, plan, versions)
	}
	started := time.Now()
	result, err := s.recordFlowSpec(ctx, principal.TenantID, plan, nil)
	if err != nil {
		return explorerResult{}, err
	}
	result.SavedFilterVersions = versions
	if len(result.Rows) > plan.PageSize {
		return explorerResult{}, apierror.Unavailable("shared flow snapshot storage is required for paged results")
	}
	rows := flowExplorerRows(result.Rows, query)
	if result.Other != nil {
		rows = append(rows, flowExplorerRows([]flowstore.PlanRow{*result.Other}, query)...)
	}
	receipt := flowExplorerReceipt(query, result, time.Since(started))
	return explorerResult{Query: query, Preview: ai.ExplorerPreview(query), Columns: explorerColumns(query), Rows: rows, Suggestions: explorerSuggestions(rows, query.Dimensions), EvidencePath: "/planes/flow", Execution: receipt, Flow: &result}, nil
}

func flowExplorerRows(input []flowstore.PlanRow, query ai.ExplorerQuery) []ai.Row {
	rows := make([]ai.Row, 0, len(input))
	for _, item := range input {
		row := ai.Row{"is_other": item.Other}
		for _, field := range query.Groupings {
			row[field] = item.Group[field]
		}
		for name, value := range item.Metrics {
			row[name] = json.Number(value)
			row[name+"_str"] = value
		}
		rows = append(rows, row)
	}
	return rows
}

func flowExplorerReceipt(query ai.ExplorerQuery, result flowstore.PlanResult, duration time.Duration) explorerExecutionReceipt {
	filterKeys := flow.QueryFilterFields(result.Query.Filter)
	sort.Strings(filterKeys)
	count := len(result.Rows)
	if result.Other != nil {
		count++
	}
	return explorerExecutionReceipt{ContractVersion: "flow-explorer-execution/v2", Recipe: explorerRecipe(query), Source: ai.ExplorerFlow, TenantScoped: true, Bounds: explorerExecutionBounds{From: result.Query.From, To: result.Query.To, RowLimit: result.Query.RowLimit}, Projection: explorerExecutionProjection{Dimensions: query.Dimensions, Groupings: query.Groupings, Measures: query.Measures}, FilterKeys: filterKeys, SourceRows: result.TotalGroups, ReturnedRows: count, TruncationReason: "none", Timings: explorerExecutionTimings{SourceMS: duration.Milliseconds(), TotalMS: duration.Milliseconds()}}
}
