// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
)

type seasonalPlanStore interface {
	exploreSeasonalWindows(context.Context, PlanQuery, []time.Time, int) ([]PlanResult, error)
}

// ExploreSeasonalWindows evaluates one pinned plan on every completed clock
// under one query, memory and cumulative-read envelope. The seasonal reader
// selects original groups; Explorer's visualization limits are presentation.
// For ranked input, the complete population is counted before returning the
// requested top keys and the first excluded original from each clock.
// DDoS reads combine equivalent non-UDP source ports after filtering the
// original source fields and preserve known intervals across short windows.
func (b *PlanBatch) ExploreSeasonalWindows(query PlanQuery, ends []time.Time, topKeys int) ([]PlanResult, error) {
	b.queryMu.Lock()
	defer b.queryMu.Unlock()
	if err := b.ctx.Err(); err != nil {
		return nil, err
	}
	if b.failed || b.queries == 0 {
		return nil, ErrExplorerBudget
	}
	if query.TenantID == "" || query.TenantID != b.tenant {
		b.failed = true
		return nil, ErrNoTenant
	}
	backend, ok := b.backend.(seasonalPlanStore)
	if !ok {
		b.failed = true
		return nil, ErrExplorerBudget
	}
	b.queries--
	if topKeys < 0 || topKeys > flow.MaxFieldComparisonKeys || topKeys != 0 && (query.Plan.View != "table" || query.Plan.RowLimit != topKeys+1) {
		b.failed = true
		return nil, ErrExplorerBudget
	}
	if (query.DDoSVerifySampling || query.DDoSProjection || query.DDoSGroupSampledExporters) && (!query.DDoSProjection || topKeys != 0 || query.Plan.View != "table" || query.Plan.DataSeries != "raw" ||
		!slices.Contains(query.Plan.GroupBy, "src_port") || !slices.Contains(query.Plan.GroupBy, "transport")) {
		b.failed = true
		return nil, ErrExplorerBudget
	}
	if query.DDoSGroupSampledExporters && (!slices.Contains(query.Plan.GroupBy, "exporter") || !slices.Contains(query.Plan.GroupBy, "sampling")) {
		b.failed = true
		return nil, ErrExplorerBudget
	}
	result, err := backend.exploreSeasonalWindows(b.queryContext(), query, ends, topKeys)
	if err != nil {
		b.failed = true
		return nil, err
	}
	return result, nil
}

func usesDDoSWindowClock(query PlanQuery, lookback time.Duration) bool {
	return query.DDoSProjection && lookback%time.Second == 0 && anomaly.DDoSFastPeriod(int(lookback/time.Second))
}

func seasonalFlowPlan(ctx context.Context, query PlanQuery, ends []time.Time, vocabulary flow.QueryVocabulary, budget ExplorerBudget) (flow.QueryPlan, seasonalFlowClockRange, error) {
	var noPlan flow.QueryPlan
	var noClocks seasonalFlowClockRange
	asOf := time.Now().UTC()
	plan, err := flow.NormalizeQueryPlanWithVocabulary(query.Plan, asOf, vocabulary)
	if err != nil {
		return noPlan, noClocks, err
	}
	if plan.Cursor != "" || query.SelectedGroups != nil || query.SelectedColumns != nil || query.SelectedChartGroups != nil || query.SelectedMatrixRows != nil {
		return noPlan, noClocks, errors.New("seasonal flow requires an unpaginated saved plan")
	}
	clocks, err := newSeasonalFlowClockRange(ctx, ends, plan.To.Sub(plan.From), asOf, budget.MemoryBytes/8)
	if err != nil {
		return noPlan, noClocks, err
	}
	if !plan.To.Equal(clocks.ends[len(clocks.ends)-1]) {
		return noPlan, noClocks, errors.New("seasonal end must match the latest completed saved plan")
	}
	if err := validatePlanCurrentProjections(ctx, query, plan); err != nil {
		return noPlan, noClocks, err
	}
	plan.From = clocks.ends[0].Add(-clocks.lookback)
	return plan, clocks, nil
}

func makeSeasonalWindowResults(ctx context.Context, span flow.QueryPlan, clocks seasonalFlowClockRange, source planSource, query PlanQuery, vocabulary flow.QueryVocabulary) ([]PlanResult, error) {
	if source.coverage == nil || !source.coverage.CompleteInputs {
		return nil, &PlanCoverageError{Reason: "seasonal windows need complete original flow inputs", ResolutionSeconds: flow.MinPlanBucketSeconds}
	}
	var identity PlanResult
	identity.Query = span
	if err := captureResultTagIdentity(&identity, query, vocabulary); err != nil {
		return nil, err
	}
	if err := captureResultCurrentProjections(ctx, &identity, query); err != nil {
		return nil, err
	}
	results := make([]PlanResult, len(clocks.ends))
	for i, end := range clocks.ends {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result := identity
		result.Query.From, result.Query.To = end.Add(-clocks.lookback), end
		result.Coverage, result.Source = source.coverage, source.kind
		result.ResolutionSeconds = source.coverage.ResolutionSeconds
		results[i] = result
	}
	return results, ctx.Err()
}
