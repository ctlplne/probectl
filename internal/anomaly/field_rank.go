// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"context"
	"errors"
	"math/big"
	"time"
)

var ErrFlowFieldCoverage = errors.New("anomaly: complete comparable flow field rankings are required")

const MaxFlowFieldRank = 300

type RankedFlowField struct {
	TenantID  string
	Key       string // framed identity produced by the scoped Explorer result
	Rank      int
	Value     string // original exact source amount
	Citation  string
	Group     map[string]string
	Secondary map[string]string
}

type FlowFieldSecondaryThreshold struct {
	Measure string
	Minimum string
}

type RankedFlowFieldWindow struct {
	TenantID       string
	ViewID         string
	ViewRevision   string
	ScopeDigest    string
	Measure        string
	From, To       time.Time
	CompleteTopSet bool
	Rows           []RankedFlowField
}

type FlowFieldRankChange struct {
	Kind         string
	Key          string
	Before       *RankedFlowField
	After        *RankedFlowField
	BeforeWindow TrainingWindow
	AfterWindow  TrainingWindow
}

// CompareFlowFieldRanks compares a complete top set for one deployed dimension
// or parent partition. Entering a top set is evidence of ranking membership;
// the old presence or amount outside that ranking remains unknown.
func CompareFlowFieldRanks(ctx context.Context, tenant string, earlier, latest RankedFlowFieldWindow, limit, minimumRankChange int, minimumAmount string, work int64, secondary ...FlowFieldSecondaryThreshold) ([]FlowFieldRankChange, error) {
	if err := checkRankedFlowFieldTenant(ctx, tenant, earlier, latest); err != nil {
		return nil, err
	}
	if err := checkRankedFlowFieldPair(earlier, latest, limit, minimumRankChange); err != nil {
		return nil, err
	}
	parser := decimalSeasonalTraining{work: work}
	minimum, err := parser.parse(minimumAmount)
	if err != nil || minimum.Sign() < 0 {
		return nil, ErrFlowFieldCoverage
	}
	old, err := admitRankedFlowFieldWindow(ctx, earlier, limit, &parser)
	if err != nil {
		return nil, err
	}
	current, err := admitRankedFlowFieldWindow(ctx, latest, limit, &parser)
	if err != nil {
		return nil, err
	}
	if err := admitFlowFieldThresholds(ctx, earlier.Measure, secondary, &parser, old, current); err != nil {
		return nil, err
	}
	return compareAdmittedRankWindows(ctx, old, current, minimumRankChange, minimum)
}

func checkRankedFlowFieldTenant(ctx context.Context, tenant string, windows ...RankedFlowFieldWindow) error {
	if tenant == "" {
		return ErrCrossTenantFeature
	}
	for _, window := range windows {
		if window.TenantID != tenant {
			return ErrCrossTenantFeature
		}
		for _, row := range window.Rows {
			if row.TenantID != tenant {
				return ErrCrossTenantFeature
			}
			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func checkRankedFlowFieldPair(before, after RankedFlowFieldWindow, limit, minimumRankChange int) error {
	if limit < 1 || limit > MaxFlowFieldRank || minimumRankChange < 1 || minimumRankChange > limit ||
		!before.CompleteTopSet || !after.CompleteTopSet || before.ViewID == "" || before.ViewID != after.ViewID ||
		before.ViewRevision == "" || before.ViewRevision != after.ViewRevision || before.ScopeDigest == "" || before.ScopeDigest != after.ScopeDigest ||
		before.Measure == "" || before.Measure != after.Measure || before.From.IsZero() || after.From.IsZero() ||
		!before.From.Before(before.To) || !after.From.Before(after.To) || before.To.After(after.From) ||
		before.To.Sub(before.From) != after.To.Sub(after.From) {
		return ErrFlowFieldCoverage
	}
	return nil
}

type admittedFlowRank struct {
	RankedFlowField
	value          *big.Rat
	comparisonRank int
	eligible       bool
}

type admittedFlowRankWindow struct {
	byKey  map[string]*admittedFlowRank
	byRank []*admittedFlowRank
	window TrainingWindow
}

func admitRankedFlowFieldWindow(ctx context.Context, window RankedFlowFieldWindow, limit int, parser *decimalSeasonalTraining) (admittedFlowRankWindow, error) {
	var none admittedFlowRankWindow
	rows := len(window.Rows)
	if rows > limit || int64(rows) > parser.work/512 {
		return none, ErrFlowFieldCoverage
	}
	parser.work -= int64(rows) * 512
	out := admittedFlowRankWindow{byKey: make(map[string]*admittedFlowRank, rows), byRank: make([]*admittedFlowRank, rows),
		window: TrainingWindow{Start: window.From, End: window.To, Samples: rows}}
	for _, row := range window.Rows {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if row.Key == "" || len(row.Key) > 128 || row.Rank < 1 || row.Rank > rows || row.Citation == "" || len(row.Citation) > 512 ||
			out.byKey[row.Key] != nil || out.byRank[row.Rank-1] != nil {
			return none, ErrFlowFieldCoverage
		}
		value, err := parser.parse(row.Value)
		if err != nil || value.Sign() < 0 {
			return none, ErrFlowFieldCoverage
		}
		recorded := &admittedFlowRank{RankedFlowField: row, value: value}
		out.byRank[row.Rank-1], out.byKey[row.Key] = recorded, recorded
	}
	for i, row := range out.byRank {
		row.comparisonRank = row.Rank
		if i == 0 {
			continue
		}
		previous := out.byRank[i-1]
		switch row.value.Cmp(previous.value) {
		case 1:
			return none, ErrFlowFieldCoverage
		case 0:
			row.comparisonRank = previous.comparisonRank
		}
	}
	return out, ctx.Err()
}

func admitFlowFieldThresholds(ctx context.Context, primary string, limits []FlowFieldSecondaryThreshold, parser *decimalSeasonalTraining, windows ...admittedFlowRankWindow) error {
	if len(limits) > 2 {
		return ErrFlowFieldCoverage
	}
	minima := make(map[string]*big.Rat, len(limits))
	for _, limit := range limits {
		if limit.Measure == "" || limit.Measure == primary || minima[limit.Measure] != nil {
			return ErrFlowFieldCoverage
		}
		minimum, err := parser.parse(limit.Minimum)
		if err != nil || minimum.Sign() < 0 {
			return ErrFlowFieldCoverage
		}
		minima[limit.Measure] = minimum
	}
	for _, window := range windows {
		for _, row := range window.byRank {
			if err := ctx.Err(); err != nil {
				return err
			}
			row.eligible = true
			for _, limit := range limits {
				value, err := parser.parse(row.Secondary[limit.Measure])
				if err != nil || value.Sign() < 0 {
					return ErrFlowFieldCoverage
				}
				row.eligible = row.eligible && value.Cmp(minima[limit.Measure]) >= 0
			}
		}
	}
	return ctx.Err()
}

func compareAdmittedRankWindows(ctx context.Context, old, current admittedFlowRankWindow, minimumRankChange int, minimum *big.Rat) ([]FlowFieldRankChange, error) {
	out := make([]FlowFieldRankChange, 0)
	for _, row := range current.byRank {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		before := old.byKey[row.Key]
		if !row.eligible || row.value.Cmp(minimum) < 0 {
			continue
		}
		if before == nil {
			out = append(out, FlowFieldRankChange{Kind: "entered_top_set", Key: row.Key, After: &row.RankedFlowField, BeforeWindow: old.window, AfterWindow: current.window})
			continue
		}
		if max(before.comparisonRank-row.comparisonRank, row.comparisonRank-before.comparisonRank) >= minimumRankChange {
			out = append(out, FlowFieldRankChange{Kind: "rank_shift", Key: row.Key, Before: &before.RankedFlowField, After: &row.RankedFlowField, BeforeWindow: old.window, AfterWindow: current.window})
		}
	}
	for _, row := range old.byRank {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if current.byKey[row.Key] == nil && row.eligible && row.value.Cmp(minimum) >= 0 {
			out = append(out, FlowFieldRankChange{Kind: "left_top_set", Key: row.Key, Before: &row.RankedFlowField, BeforeWindow: old.window, AfterWindow: current.window})
		}
	}
	return out, ctx.Err()
}
