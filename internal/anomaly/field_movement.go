// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"context"
	"math/big"
)

type FlowFieldDistributionWindow struct {
	Ranking     RankedFlowFieldWindow
	ParentTotal string // exact total from the complete parent population
}

type FlowFieldShareChange struct {
	Key          string
	Direction    string
	Before       RankedFlowField
	After        RankedFlowField
	BeforeShare  string // canonical rational fraction of the entire parent
	AfterShare   string
	BeforeWindow TrainingWindow
	AfterWindow  TrainingWindow
}

// CompareFlowFieldShares reports port or protocol share shifts for members
// with known denominators and observed amounts in both complete windows.
func CompareFlowFieldShares(ctx context.Context, tenant string, earlier, latest FlowFieldDistributionWindow, limit, changeBasisPoints int, work int64) ([]FlowFieldShareChange, error) {
	if err := checkRankedFlowFieldTenant(ctx, tenant, earlier.Ranking, latest.Ranking); err != nil {
		return nil, err
	}
	if err := checkRankedFlowFieldPair(earlier.Ranking, latest.Ranking, limit, 1); err != nil {
		return nil, err
	}
	if !FlowFieldAdditiveMeasure(earlier.Ranking.Measure) || changeBasisPoints < 1 || changeBasisPoints > 10000 {
		return nil, ErrFlowFieldCoverage
	}
	parser := decimalSeasonalTraining{work: work}
	before, beforeTotal, err := admitFlowDistribution(ctx, earlier, limit, &parser)
	if err != nil {
		return nil, err
	}
	after, afterTotal, err := admitFlowDistribution(ctx, latest, limit, &parser)
	if err != nil {
		return nil, err
	}
	threshold := big.NewRat(int64(changeBasisPoints), 10000)
	return compareFlowShares(ctx, before, after, beforeTotal, afterTotal, threshold)
}

func FlowFieldAdditiveMeasure(measure string) bool {
	switch measure {
	case "bytes:total", "packets:total", "flows:total",
		"bps:total", "pps:total", "fps:total", "bps:avg", "pps:avg", "fps:avg":
		return true
	default:
		return false
	}
}

func admitFlowDistribution(ctx context.Context, input FlowFieldDistributionWindow, limit int, parser *decimalSeasonalTraining) (admittedFlowRankWindow, *big.Rat, error) {
	var none admittedFlowRankWindow
	total, err := parser.parse(input.ParentTotal)
	if err != nil || total.Sign() <= 0 {
		return none, nil, ErrFlowFieldCoverage
	}
	window, err := admitRankedFlowFieldWindow(ctx, input.Ranking, limit, parser)
	if err != nil {
		return none, nil, err
	}
	visible := new(big.Rat)
	for _, row := range window.byRank {
		visible.Add(visible, row.value)
	}
	if visible.Cmp(total) > 0 {
		return none, nil, ErrFlowFieldCoverage
	}
	return window, total, ctx.Err()
}

func compareFlowShares(ctx context.Context, before, after admittedFlowRankWindow, beforeTotal, afterTotal, threshold *big.Rat) ([]FlowFieldShareChange, error) {
	out := make([]FlowFieldShareChange, 0)
	for _, current := range after.byRank {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		original := before.byKey[current.Key]
		if original == nil {
			continue // ranking movement already describes this member's appearance
		}
		oldShare := new(big.Rat).Quo(original.value, beforeTotal)
		newShare := new(big.Rat).Quo(current.value, afterTotal)
		delta := new(big.Rat).Sub(newShare, oldShare)
		direction := "up"
		if delta.Sign() < 0 {
			direction = "down"
		}
		if delta.Abs(delta).Cmp(threshold) >= 0 {
			out = append(out, FlowFieldShareChange{Key: current.Key, Direction: direction, Before: original.RankedFlowField, After: current.RankedFlowField,
				BeforeShare: oldShare.RatString(), AfterShare: newShare.RatString(), BeforeWindow: before.window, AfterWindow: after.window})
		}
	}
	return out, ctx.Err()
}

type FlowFieldAmountChange struct {
	Key          string
	Delta        string
	Before       RankedFlowField
	After        RankedFlowField
	BeforeWindow TrainingWindow
	AfterWindow  TrainingWindow
}

// CompareFlowFieldAmounts preserves the exact signed change for a member
// observed in both equally long windows. It never supplies a missing amount.
func CompareFlowFieldAmounts(ctx context.Context, tenant string, earlier, latest RankedFlowFieldWindow, limit int, minimumChange string, work int64) ([]FlowFieldAmountChange, error) {
	if err := checkRankedFlowFieldTenant(ctx, tenant, earlier, latest); err != nil {
		return nil, err
	}
	if err := checkRankedFlowFieldPair(earlier, latest, limit, 1); err != nil {
		return nil, err
	}
	parser := decimalSeasonalTraining{work: work}
	minimum, err := parser.parse(minimumChange)
	if err != nil || minimum.Sign() <= 0 {
		return nil, ErrFlowFieldCoverage
	}
	before, err := admitRankedFlowFieldWindow(ctx, earlier, limit, &parser)
	if err != nil {
		return nil, err
	}
	after, err := admitRankedFlowFieldWindow(ctx, latest, limit, &parser)
	if err != nil {
		return nil, err
	}
	changes := make([]FlowFieldAmountChange, 0)
	for _, current := range after.byRank {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		original := before.byKey[current.Key]
		if original == nil {
			continue
		}
		difference := new(big.Rat).Sub(current.value, original.value)
		if new(big.Rat).Abs(difference).Cmp(minimum) >= 0 {
			changes = append(changes, FlowFieldAmountChange{Key: current.Key, Delta: difference.RatString(), Before: original.RankedFlowField,
				After: current.RankedFlowField, BeforeWindow: before.window, AfterWindow: after.window})
		}
	}
	return changes, ctx.Err()
}

type FlowFanoutChange struct {
	SourceKey    string
	Before       RankedFlowField
	After        RankedFlowField
	BeforeWindow TrainingWindow
	AfterWindow  TrainingWindow
}

// CompareFlowFanout reports increases in the exact distinct destination count
// for the same observed source. The adapter supplies unique_dst:total from
// the admitted per-source distinct reader and checks retained field coverage.
func CompareFlowFanout(ctx context.Context, tenant string, earlier, latest RankedFlowFieldWindow, limit int, minimumIncrease string, work int64) ([]FlowFanoutChange, error) {
	if err := checkRankedFlowFieldTenant(ctx, tenant, earlier, latest); err != nil {
		return nil, err
	}
	if err := checkRankedFlowFieldPair(earlier, latest, limit, 1); err != nil {
		return nil, err
	}
	if earlier.Measure != "unique_dst:total" {
		return nil, ErrFlowFieldCoverage
	}
	parser := decimalSeasonalTraining{work: work}
	floor, err := parser.parse(minimumIncrease)
	if err != nil || !floor.IsInt() || floor.Sign() <= 0 {
		return nil, ErrFlowFieldCoverage
	}
	before, err := admitRankedFlowFieldWindow(ctx, earlier, limit, &parser)
	if err != nil {
		return nil, err
	}
	after, err := admitRankedFlowFieldWindow(ctx, latest, limit, &parser)
	if err != nil {
		return nil, err
	}
	return compareAdmittedFlowFanout(ctx, before, after, floor)
}

func compareAdmittedFlowFanout(ctx context.Context, before, after admittedFlowRankWindow, floor *big.Rat) ([]FlowFanoutChange, error) {
	for _, row := range before.byRank {
		if !row.value.IsInt() {
			return nil, ErrFlowFieldCoverage
		}
	}
	out := make([]FlowFanoutChange, 0)
	for _, row := range after.byRank {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !row.value.IsInt() {
			return nil, ErrFlowFieldCoverage
		}
		prior := before.byKey[row.Key]
		if prior == nil || new(big.Rat).Sub(row.value, prior.value).Cmp(floor) < 0 {
			continue
		}
		out = append(out, FlowFanoutChange{SourceKey: row.Key, Before: prior.RankedFlowField, After: row.RankedFlowField, BeforeWindow: before.window, AfterWindow: after.window})
	}
	return out, ctx.Err()
}
