// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
)

type nativeMCPFlowBackend struct{ server *Server }

var _ mcp.NativeFlowBackend = nativeMCPFlowBackend{}

func (b nativeMCPFlowBackend) FlowPlan(ctx context.Context, p *auth.Principal, input mcp.NativeFlowQuestionInput) (mcp.NativeFlowQuestionResult, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowQuestionResult{}, err
	}
	result, err := b.server.planFlowQuestion(ctx, p, input.Question)
	if err != nil {
		return mcp.NativeFlowQuestionResult{}, err
	}
	proposal := result.Proposal
	out := mcp.NativeFlowQuestionProposal{Status: string(proposal.Status), Plan: proposal.Plan, Comparison: proposal.Comparison, Display: proposal.Display, Guidance: proposal.Guidance, Assumptions: proposal.Assumptions, NeedsConfirmation: proposal.NeedsConfirmation}
	if proposal.Previous != nil {
		out.Previous = &mcp.NativeFlowQuestionPeriod{From: proposal.Previous.From, To: proposal.Previous.To}
	}
	return mcp.NativeFlowQuestionResult{Proposal: out}, nil
}

func (b nativeMCPFlowBackend) authorize(ctx context.Context, p *auth.Principal) error {
	if b.server == nil {
		return apierror.Unavailable("native flow services are unavailable")
	}
	if _, err := flowSnapshotScope(p); err != nil {
		return err
	}
	return b.server.authorizeNativeFlow(ctx, p)
}
func (s *Server) beginNativeMCPQuery(ctx context.Context, p *auth.Principal) (func(), error) {
	if err := (nativeMCPFlowBackend{s}).authorize(ctx, p); err != nil {
		return nil, err
	}
	if s.fairnessGate == nil {
		return func() {}, nil
	}
	return s.fairnessGate.BeginQuery(ctx, p.TenantID)
}
func (b nativeMCPFlowBackend) FlowSchema(ctx context.Context, p *auth.Principal) (mcp.NativeFlowSchemaResult, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowSchemaResult{}, err
	}
	out := mcp.NativeFlowSchemaResult{ContractVersion: "flow-explorer/v2", Fields: []mcp.NativeFlowField{}, Metrics: []mcp.NativeFlowMetric{}, TimeRange: "tenant retention and source coverage; no fixed day cap"}
	out.RenderCost = b.server.flowRenderBudget
	fields, err := b.server.flowQueryFields(ctx, p)
	if err != nil {
		return mcp.NativeFlowSchemaResult{}, err
	}
	for _, f := range fields {
		out.Fields = append(out.Fields, mcp.NativeFlowField{Name: f.Name, Type: f.Type, Operators: f.Operators, LegacyHourly: f.LegacyHourly, Raw: f.Raw, Rollup: f.Rollup, Permission: f.Permission})
	}
	for _, m := range flow.QueryMetricDefinitions() {
		values := []mcp.NativeFlowCalculation{}
		for _, c := range m.Calculations {
			values = append(values, mcp.NativeFlowCalculation{Name: c, Unit: m.CalculationUnits[c]})
		}
		out.Metrics = append(out.Metrics, mcp.NativeFlowMetric{Name: m.Name, Unit: m.Unit, DistinctField: m.DistinctField, Calculations: values})
	}
	budget := flowstore.ExplorerQueryBudget(b.server.flowStore)
	out.Limits = mcp.NativeFlowLimits{MaxGroups: flow.MaxPlanDimensions, MaxMatrixDimensions: flow.MaxPlanMatrixDimensions, MaxMatrixDepth: flow.MaxPlanMatrixDepth, MaxChartSeries: flow.MaxPlanChartSeries, MaxChartRows: flow.MaxPlanChartRows, MaxTableRows: flow.MaxPlanTableRows, MaxPageRows: flow.MaxPlanPageRows, MinBucketSeconds: flow.MinPlanBucketSeconds, MaxBucketSeconds: flow.MaxPlanBucketSeconds, MaxGroupEntries: flow.MaxQueryGroupEntries, MaxExpandedConditions: flow.MaxQueryPredicates, MaxFilterDepth: flow.MaxQueryFilterDepth, MaxRegexBytes: flow.MaxQueryRegexBytes, MaxValuesPerPredicate: flow.MaxQueryValues, MaxValueBytes: flow.MaxQueryValueBytes, MaxTagValueCharacters: tags.MaxValueCharacters, MaxTagValueBytes: tags.MaxValueBytes, GrammarBytes: flow.MaxPlanGrammarBytes, ExecutionSeconds: budget.ExecutionLimit.Seconds(), ReadBytes: budget.ReadBytes, ReadRows: budget.ReadRows, ResponseBytes: budget.ResponseBytes, MemoryBytes: budget.MemoryBytes, IntermediateGroups: budget.IntermediateGroups, InterfaceItems: budget.InterfaceItems, Threads: budget.Threads}
	out.Defaults = mcp.NativeFlowDefaults{IPv4PrefixLength: 24, IPv6PrefixLength: 48, BucketSeconds: 60, SeriesDepth: 40, RowLimit: 100}
	out.Statistics = mcp.NativeFlowStatistics{Percentile: "nearest rank, including idle zero buckets", RateAverage: "duration weighted", DecimalPlaces: 18, DecimalRounding: "toward zero", DistinctTotal: "whole-window exact identities", DistinctBucketTotal: "sum of per-bucket distinct counts"}
	return out, nil
}
func (b nativeMCPFlowBackend) FlowQuery(ctx context.Context, p *auth.Principal, plan flow.QueryPlan) (mcp.NativeFlowQueryResult, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowQueryResult{}, err
	}
	if plan.Cursor != "" {
		result, err := b.server.resumeFlowSnapshot(ctx, p, ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: &plan})
		if err != nil {
			return mcp.NativeFlowQueryResult{}, err
		}
		return projectNativeFlowQuery(result, p.TenantID)
	}
	query, queryCtx, err := b.server.normalizeExplorerQuery(ctx, p,
		ai.ExplorerQuery{Question: "Native flow query", Source: ai.ExplorerFlow, Flow: &plan}, time.Now())
	if err != nil {
		return mcp.NativeFlowQueryResult{}, err
	}
	result, err := b.server.recordFlowQuery(queryCtx, p, query)
	if err != nil {
		return mcp.NativeFlowQueryResult{}, err
	}
	return projectNativeFlowQuery(result, p.TenantID)
}
func (b nativeMCPFlowBackend) FlowCompare(ctx context.Context, p *auth.Principal, input mcp.NativeFlowCompareInput) (mcp.NativeFlowComparisonResult, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowComparisonResult{}, err
	}
	if input.Plan.Cursor != "" || input.PreviousFrom.IsZero() || !input.PreviousFrom.Before(input.PreviousTo) {
		return mcp.NativeFlowComparisonResult{}, apierror.Validation("native flow comparison requires explicit previous bounds and no cursor")
	}
	now := time.Now()
	query, queryCtx, err := b.server.normalizeExplorerQuery(ctx, p,
		ai.ExplorerQuery{Question: "Native flow comparison", Source: ai.ExplorerFlow, Flow: &input.Plan}, now)
	if err != nil {
		return mcp.NativeFlowComparisonResult{}, err
	}
	previous := query
	plan := *query.Flow
	plan.From = input.PreviousFrom
	plan.To = input.PreviousTo
	previous.From = plan.From
	previous.To = plan.To
	previous.Flow = &plan
	previous, queryCtx, err = b.server.normalizeExplorerQuery(queryCtx, p, previous, now)
	if err != nil {
		return mcp.NativeFlowComparisonResult{}, err
	}
	result, err := b.server.recordFlowComparison(queryCtx, p, query, previous)
	if err != nil {
		return mcp.NativeFlowComparisonResult{}, err
	}
	return projectNativeFlowComparison(result, p.TenantID)
}
func (b nativeMCPFlowBackend) FlowPage(ctx context.Context, p *auth.Principal, cursor string) (mcp.NativeFlowQueryResult, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowQueryResult{}, err
	}
	result, err := b.server.resumeFlowSnapshot(ctx, p, ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: &flow.QueryPlan{Cursor: cursor}})
	if err != nil {
		return mcp.NativeFlowQueryResult{}, err
	}
	return projectNativeFlowQuery(result, p.TenantID)
}
func (b nativeMCPFlowBackend) FlowComparisonPage(ctx context.Context, p *auth.Principal, cursor string) (mcp.NativeFlowComparisonResult, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowComparisonResult{}, err
	}
	result, err := b.server.resumeFlowComparisonSnapshot(ctx, p, ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: &flow.QueryPlan{Cursor: cursor}})
	if err != nil {
		return mcp.NativeFlowComparisonResult{}, err
	}
	return projectNativeFlowComparison(result, p.TenantID)
}
func (b nativeMCPFlowBackend) FlowFilters(ctx context.Context, p *auth.Principal, after string, limit int) (mcp.NativeFlowFilterPage, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowFilterPage{}, err
	}
	if limit == 0 {
		limit = 100
	}
	page, err := b.server.listFlowFilters(ctx, p, after, limit)
	if err != nil {
		return mcp.NativeFlowFilterPage{}, err
	}
	out := mcp.NativeFlowFilterPage{Items: []mcp.NativeFlowFilter{}, Next: page.Next}
	for _, item := range page.Items {
		out.Items = append(out.Items, projectNativeFlowFilter(item))
	}
	return out, nil
}
func (b nativeMCPFlowBackend) FlowFilter(ctx context.Context, p *auth.Principal, id string) (mcp.NativeFlowFilter, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowFilter{}, err
	}
	item, err := b.server.getFlowFilter(ctx, p, id)
	if err != nil {
		return mcp.NativeFlowFilter{}, err
	}
	return projectNativeFlowFilter(item), nil
}
func (b nativeMCPFlowBackend) SaveFlowFilter(ctx context.Context, p *auth.Principal, input mcp.NativeFlowFilterInput) (mcp.NativeFlowFilter, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowFilter{}, err
	}
	version := int64(0)
	if input.Version != "" {
		var err error
		version, err = strconv.ParseInt(input.Version, 10, 64)
		if err != nil || version < 1 || strconv.FormatInt(version, 10) != input.Version {
			return mcp.NativeFlowFilter{}, apierror.Validation("native filter revision must be exact positive decimal text")
		}
	}
	item, err := b.server.saveFlowFilterDefinition(ctx, p, flow.SaveQueryFilter{ID: input.ID, Version: version, Name: input.Name, Description: input.Description, Expression: input.Expression})
	if err != nil {
		return mcp.NativeFlowFilter{}, err
	}
	return projectNativeFlowFilter(item), nil
}
func (b nativeMCPFlowBackend) DeleteFlowFilter(ctx context.Context, p *auth.Principal, id, version string) (mcp.NativeFlowMutationResult, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowMutationResult{}, err
	}
	if err := b.server.deleteFlowFilter(ctx, p, id, []string{version}); err != nil {
		return mcp.NativeFlowMutationResult{}, err
	}
	return mcp.NativeFlowMutationResult{ID: id, Updated: true}, nil
}
func (b nativeMCPFlowBackend) FlowViews(ctx context.Context, p *auth.Principal, input mcp.NativeFlowViewListInput) (mcp.NativeFlowViewPage, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowViewPage{}, err
	}
	page, err := b.server.listFlowViews(ctx, p, flow.QueryViewList{After: input.After, Limit: input.Limit, Search: input.Search, Label: input.Label, Visibility: input.Visibility, Owner: input.Owner, Sort: input.Sort, Tab: input.Tab})
	if err != nil {
		return mcp.NativeFlowViewPage{}, err
	}
	out := mcp.NativeFlowViewPage{Items: []mcp.NativeFlowView{}, Next: page.Next}
	for _, item := range page.Items {
		out.Items = append(out.Items, projectNativeFlowView(item))
	}
	return out, nil
}
func (b nativeMCPFlowBackend) FlowView(ctx context.Context, p *auth.Principal, id string) (mcp.NativeFlowView, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowView{}, err
	}
	item, err := b.server.getFlowViewByID(ctx, p, id)
	if err != nil {
		return mcp.NativeFlowView{}, err
	}
	return projectNativeFlowView(item), nil
}
func (b nativeMCPFlowBackend) SaveFlowView(ctx context.Context, p *auth.Principal, input flow.SaveQueryView) (mcp.NativeFlowView, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowView{}, err
	}
	item, err := b.server.saveFlowViewDefinition(ctx, p, input)
	if err != nil {
		return mcp.NativeFlowView{}, err
	}
	return projectNativeFlowView(item), nil
}
func (b nativeMCPFlowBackend) DeleteFlowView(ctx context.Context, p *auth.Principal, id, version string) (mcp.NativeFlowMutationResult, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowMutationResult{}, err
	}
	if err := b.server.deleteFlowView(ctx, p, id, []string{version}); err != nil {
		return mcp.NativeFlowMutationResult{}, err
	}
	return mcp.NativeFlowMutationResult{ID: id, Updated: true}, nil
}
func (b nativeMCPFlowBackend) FavoriteFlowView(ctx context.Context, p *auth.Principal, id string, favorite bool) (mcp.NativeFlowMutationResult, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowMutationResult{}, err
	}
	if err := b.server.setFlowViewFavorite(ctx, p, id, &favorite); err != nil {
		return mcp.NativeFlowMutationResult{}, err
	}
	return mcp.NativeFlowMutationResult{ID: id, Updated: true}, nil
}
func (b nativeMCPFlowBackend) RunFlowView(ctx context.Context, p *auth.Principal, id string) (mcp.NativeFlowExecution, error) {
	if err := b.authorize(ctx, p); err != nil {
		return mcp.NativeFlowExecution{}, err
	}
	result, err := b.server.runFlowView(ctx, p, id)
	if err != nil {
		return mcp.NativeFlowExecution{}, err
	}
	switch {
	case result.Query != nil:
		query, err := projectNativeFlowQuery(*result.Query, p.TenantID)
		if err != nil {
			return mcp.NativeFlowExecution{}, err
		}
		return mcp.NativeFlowExecution{Query: &query}, nil
	case result.Comparison != nil:
		comparison, err := projectNativeFlowComparison(*result.Comparison, p.TenantID)
		if err != nil {
			return mcp.NativeFlowExecution{}, err
		}
		return mcp.NativeFlowExecution{Comparison: &comparison}, nil
	default:
		return mcp.NativeFlowExecution{}, nativeFlowProjectionError()
	}
}
