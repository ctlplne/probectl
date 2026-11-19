// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) projectNativeFlowFieldComparison(ctx context.Context, actor *auth.Principal, source flow.FieldComparison) (mcp.NativeFlowFieldComparison, error) {
	var empty mcp.NativeFlowFieldComparison
	bound, ok := tenancy.FromContext(ctx)
	if !ok || actor == nil || bound.String() != actor.TenantID {
		return empty, tenancy.ErrNoTenant
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return empty, nativeFlowProjectionError()
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	ctx, err := s.withFlowViewVocabulary(ctx, actor)
	if err != nil {
		return empty, err
	}
	vocabulary, _, err := flow.QueryVocabularyFromContext(ctx, actor.TenantID)
	if err != nil {
		return empty, err
	}
	if source.TopKeys < 1 || source.TopKeys > flow.MaxFieldComparisonKeys || source.Changes == nil || len(source.Changes) > 2*source.TopKeys {
		return empty, nativeFlowProjectionError()
	}
	result := mcp.NativeFlowFieldComparison{ViewID: source.ViewID, Version: source.Version, Mode: source.Mode, Measure: source.Measure,
		Cadence: source.Cadence, TopKeys: source.TopKeys, Before: source.Before, After: source.After, History: source.History,
		Changes: make([]mcp.NativeFlowFieldChange, 0, len(source.Changes))}
	for _, change := range source.Changes {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if len(change.Group) == 0 || len(change.Group) > flow.MaxPlanDimensions {
			return empty, nativeFlowProjectionError()
		}
		group, err := nativeFlowDimensions(slices.Sorted(maps.Keys(change.Group)), change.Group, false, vocabulary)
		if err != nil {
			return empty, err
		}
		before, err := projectNativeFlowFieldObservation(change.Before, source.Measure)
		if err != nil {
			return empty, err
		}
		after, err := projectNativeFlowFieldObservation(change.After, source.Measure)
		if err != nil {
			return empty, err
		}
		result.Changes = append(result.Changes, mcp.NativeFlowFieldChange{Kind: change.Kind, Key: change.Key,
			Group: group, Before: before, After: after, Delta: change.Delta})
	}
	return result, ctx.Err()
}

func projectNativeFlowFieldObservation(source *flow.FieldObservation, primary string) (*mcp.NativeFlowFieldObservation, error) {
	if source == nil {
		return nil, nil
	}
	result := &mcp.NativeFlowFieldObservation{Rank: source.Rank, Value: source.Value, Share: source.Share, Citation: source.Citation}
	if len(source.Secondary) == 0 {
		return result, nil
	}
	if len(source.Secondary) > 3 {
		return nil, nativeFlowProjectionError()
	}
	measure, calculation, ok := strings.Cut(primary, ":")
	if !ok {
		return nil, nativeFlowProjectionError()
	}
	metrics := []flow.QueryMetric{{Measure: measure, Calculation: calculation, Role: "primary"}}
	for _, key := range slices.Sorted(maps.Keys(source.Secondary)) {
		measure, calculation, ok := strings.Cut(key, ":")
		if !ok {
			return nil, nativeFlowProjectionError()
		}
		metrics = append(metrics, flow.QueryMetric{Measure: measure, Calculation: calculation, Role: "secondary"})
	}
	validated, err := flow.NormalizeQueryMetrics(metrics)
	if err != nil || !slices.Equal(metrics, validated) {
		return nil, nativeFlowProjectionError()
	}
	result.Secondary, err = nativeFlowValues(validated[1:], source.Secondary, false)
	if err != nil {
		return nil, err
	}
	return result, nil
}
