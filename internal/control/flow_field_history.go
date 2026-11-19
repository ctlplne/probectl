// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Only the latest qualifying entrants require membership state. Walk every
// requested clock even once all such candidates are known.
func compareHistoricalFlowFields(ctx context.Context, capture *reportFlowCapture, settings flowFieldComparisonSettings,
	clocks anomaly.FlowFieldComparisonClocks, work int64) (flow.FieldComparison, error) {
	var none flow.FieldComparison
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || capture == nil || tenant.String() != capture.TenantID {
		return none, tenancy.ErrNoTenant
	}
	hours := clocks.History.Samples
	if hours == 0 || hours != anomaly.FlowFieldHistoryHours(anomaly.FlowFieldComparisonCadence(settings.Cadence)) ||
		len(capture.Results) != hours+1 || !matchFlowEvidenceInputClocks(capture.Inputs, settings.View, clocks) {
		return none, anomaly.ErrFlowFieldCoverage
	}
	pair := &reportFlowCapture{
		TenantID: capture.TenantID, SourceGeneration: capture.SourceGeneration, FilterVersions: capture.FilterVersions,
		Results: capture.Results[hours-1:], Inputs: capture.Inputs[hours-1:],
	}
	current := pair.Results[1]
	scope, err := flowEvidenceAuthorityDigest(capture, settings.View, current)
	if err != nil {
		return none, err
	}
	comparison, err := compareCapturedFlowFields(ctx, pair, settings, work/4)
	if err != nil {
		return none, err
	}
	candidates := make(map[string]bool)
	for _, entry := range comparison.Changes {
		if entry.Kind == "entered_top_set" {
			candidates[entry.Key] = true
		}
	}
	available := work / 2
	for i, historical := range capture.Results[:hours-1] {
		input := capture.Inputs[i]
		if !historical.Result.Query.From.Equal(input.From) || !historical.Result.Query.To.Equal(input.To) ||
			historical.Result.TagRevision != current.Result.TagRevision || !historical.TagAsOf.Equal(current.TagAsOf) ||
			historical.Result.RoleDigest != current.Result.RoleDigest || historical.Result.RoutingProof != current.Result.RoutingProof ||
			historical.Result.Source != current.Result.Source || historical.Result.ResolutionSeconds != current.Result.ResolutionSeconds {
			return none, anomaly.ErrFlowFieldCoverage
		}
		cost := int64(len(historical.Result.Rows)+1) * 512
		if cost > available {
			return none, anomaly.ErrFlowFieldCoverage
		}
		available -= cost
		observed, err := projectRankedFlowField(ctx, historical, settings.View, scope, settings.Measure, settings.TopKeys, work/8)
		if err != nil {
			return none, err
		}
		for _, row := range observed.Ranking.Rows {
			delete(candidates, row.Key)
		}
	}
	changes := comparison.Changes[:0]
	for _, entry := range comparison.Changes {
		if candidates[entry.Key] {
			changes = append(changes, entry)
		}
	}
	comparison.Changes = changes
	comparison.History = &flow.FieldComparisonHistory{From: clocks.History.Start, To: clocks.History.End, Hours: hours}
	return comparison, ctx.Err()
}
