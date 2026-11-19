// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

func TestCompleteFieldRankReplayKeepsThreeHundredKeysAndTenant(t *testing.T) {
	const tenant = "owned-flow"
	before := fieldReplayWindow(tenant, "bytes:total", 0, MaxFlowFieldRank)
	normal := fieldReplayWindow(tenant, before.Measure, 1, MaxFlowFieldRank)
	changes, err := CompareFlowFieldRanks(t.Context(), tenant, before, normal, MaxFlowFieldRank, 3, "1", 4<<20)
	if err != nil || len(changes) != 0 {
		t.Fatal("normal comparable ranking produced an event", changes, err)
	}
	after := normal
	after.Rows = slices.Clone(normal.Rows)
	after.Rows[MaxFlowFieldRank-1].Key = "entered-client"
	after.Rows[MaxFlowFieldRank-1].Citation = "original-flow-row:entered-client"
	changes, err = CompareFlowFieldRanks(t.Context(), tenant, before, after, MaxFlowFieldRank, 3, "1", 4<<20)
	if err != nil || len(changes) != 2 || changes[0].Kind != "entered_top_set" || changes[0].Key != "entered-client" ||
		changes[0].Before != nil || changes[0].After == nil || changes[0].After.Rank != MaxFlowFieldRank || !changes[0].BeforeWindow.Start.Equal(before.From) ||
		!changes[0].AfterWindow.End.Equal(after.To) || changes[1].Kind != "left_top_set" || changes[1].After != nil {
		t.Fatal("the exact bounded population did not give two cited membership transitions", changes, err)
	}
	after.Rows[MaxFlowFieldRank-1].TenantID = "sibling"
	changes, err = CompareFlowFieldRanks(t.Context(), tenant, before, after, MaxFlowFieldRank, 3, "1", 4<<20)
	if !errors.Is(err, ErrCrossTenantFeature) || len(changes) != 0 {
		t.Fatal("a mixed input reached flow field grouping", err)
	}
}

func TestFieldRankDoesNotTreatAReorderedTieAsTrafficMovement(t *testing.T) {
	const tenant = "owned-flow"
	before := fieldReplayWindow(tenant, "bytes:total", 0, 3)
	after := fieldReplayWindow(tenant, before.Measure, 1, 3)
	before.Rows[1].Value = before.Rows[0].Value
	after.Rows[1].Value = after.Rows[0].Value
	after.Rows[0], after.Rows[1] = after.Rows[1], after.Rows[0]
	after.Rows[0].Rank, after.Rows[1].Rank = 1, 2
	changes, err := CompareFlowFieldRanks(t.Context(), tenant, before, after, 3, 1, "1", 1<<20)
	if err != nil || len(changes) != 0 {
		t.Fatal("an unchanged tied population was mistaken for movement", changes, err)
	}
}

func TestFieldRankChecksBothSecondaryThresholdsWithoutChangingMembership(t *testing.T) {
	const tenant = "owned-flow"
	before := fieldReplayWindow(tenant, "bytes:total", 0, 2)
	after := fieldReplayWindow(tenant, before.Measure, 1, 2)
	after.Rows[1].Key = "new-member"
	for _, window := range []RankedFlowFieldWindow{before, after} {
		for i := range window.Rows {
			window.Rows[i].Secondary = map[string]string{"packets:total": "10", "flows:total": "1"}
		}
	}
	after.Rows[1].Secondary["flows:total"] = "2"
	assert := func(minimum string, wanted int) {
		t.Helper()
		events, err := CompareFlowFieldRanks(t.Context(), tenant, before, after, 2, 1, "1", 1<<20,
			FlowFieldSecondaryThreshold{"packets:total", "10"}, FlowFieldSecondaryThreshold{"flows:total", minimum})
		if err != nil || len(events) != wanted || wanted == 1 && (events[0].Key != "new-member" || events[0].After.Rank != 2) {
			t.Fatal("secondary conditions changed cohort positions or admitted a below-floor observation", events, err)
		}
	}
	assert("2", 1)
	assert("3", 0)
	delete(after.Rows[1].Secondary, "flows:total")
	events, err := CompareFlowFieldRanks(t.Context(), tenant, before, after, 2, 1, "1", 1<<20,
		FlowFieldSecondaryThreshold{"packets:total", "10"}, FlowFieldSecondaryThreshold{"flows:total", "1"})
	if !errors.Is(err, ErrFlowFieldCoverage) || len(events) != 0 {
		t.Fatal("unknown secondary evidence was treated as a zero", err)
	}
}

func TestFieldMovementReplaysSharesAndExactDistinctDestinations(t *testing.T) {
	const tenant = "owned-flow"
	old := fieldReplayWindow(tenant, "bytes:total", 0, 2)
	newer := fieldReplayWindow(tenant, old.Measure, 1, 2)
	old.Rows[0].Value, old.Rows[1].Value = "100", "100"
	newer.Rows[0].Value, newer.Rows[1].Value = "150", "50"
	moves, err := CompareFlowFieldShares(t.Context(), tenant, FlowFieldDistributionWindow{old, "200"}, FlowFieldDistributionWindow{newer, "200"}, 2, 2500, 4<<20)
	if err != nil || len(moves) != 2 || moves[0].BeforeShare != "1/2" || moves[0].AfterShare != "3/4" || moves[0].Direction != "up" || moves[1].Direction != "down" {
		t.Fatal("shift was computed against a partial or wrong parent", moves, err)
	}
	original := fieldReplayWindow(tenant, "unique_dst:total", 0, 1)
	current := fieldReplayWindow(tenant, original.Measure, 1, 1)
	original.Rows[0].Value, current.Rows[0].Value = "9007199254740993", "9007199254740995"
	fanout, err := CompareFlowFanout(t.Context(), tenant, original, current, 1, "2", 4<<20)
	if err != nil || len(fanout) != 1 || fanout[0].Before.Value != "9007199254740993" || fanout[0].After.Value != "9007199254740995" {
		t.Fatal("exact distinct increase was rounded or lost", fanout, err)
	}
	current.CompleteTopSet = false
	fanout, err = CompareFlowFanout(t.Context(), tenant, original, current, 1, "2", 4<<20)
	if !errors.Is(err, ErrFlowFieldCoverage) || len(fanout) != 0 {
		t.Fatal("partial input was mistaken for a known baseline", err)
	}
}

func TestFieldAmountKeepsSubunitDeltaAndUnobservedValues(t *testing.T) {
	const tenant = "owned-flow"
	before := fieldReplayWindow(tenant, "bps:avg", 0, 2)
	after := fieldReplayWindow(tenant, before.Measure, 1, 2)
	before.Rows[0].Value = "9007199254740992.99"
	after.Rows[0].Value = "9007199254740993.00"
	after.Rows[1].Key = "outside-prior-top-set"
	changes, err := CompareFlowFieldAmounts(t.Context(), tenant, before, after, 2, "0.01", 4<<20)
	if err != nil || len(changes) != 1 || changes[0].Delta != "1/100" || changes[0].After.Value != after.Rows[0].Value {
		t.Fatal("comparison rounded the measured delta or invented a value for the absent source", changes, err)
	}
}

func TestFieldClocksAlignEveryCadenceToCompletedUTCWindows(t *testing.T) {
	clock := time.Date(2026, 1, 12, 5, 6, 7, 8, time.FixedZone("operator", 9*3600))
	for _, seconds := range []int{60, 120, 300} {
		period := time.Duration(seconds) * time.Second
		for _, cadence := range []FlowFieldComparisonCadence{FlowFieldPreviousPeriod, FlowFieldPreviousWeek} {
			windows, err := FlowFieldCompletedWindows(clock, cadence, seconds)
			if err != nil || !windows.After.End.Equal(clock.UTC().Truncate(period)) || windows.After.End.Location() != time.UTC ||
				windows.Before.End.Sub(windows.Before.Start) != period || windows.After.End.Sub(windows.After.Start) != period {
				t.Fatal("a window included an incomplete interval or followed the client time zone", cadence, seconds, windows, err)
			}
			if cadence == FlowFieldPreviousWeek && windows.After.End.Sub(windows.Before.End) != 7*24*time.Hour ||
				cadence == FlowFieldPreviousPeriod && !windows.Before.End.Equal(windows.After.Start) {
				t.Fatal("comparison used the wrong reference period", cadence, seconds, windows)
			}
		}
	}
	weeks, err := FlowFieldCompletedWindows(clock, FlowFieldCompleteWeek, 0)
	if err != nil || !weeks.After.End.Equal(time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)) ||
		weeks.After.End.Sub(weeks.Before.Start) != 14*24*time.Hour || !weeks.After.Start.Equal(weeks.Before.End) {
		t.Fatal("complete week comparison included the current UTC date", weeks, err)
	}
}

func fieldReplayWindow(tenant, measure string, hours, rows int) RankedFlowFieldWindow {
	first := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC).Add(time.Duration(hours) * time.Hour)
	window := RankedFlowFieldWindow{TenantID: tenant, ViewID: "owned-view", ViewRevision: "8", ScopeDigest: "parent-source", Measure: measure,
		From: first, To: first.Add(2 * time.Minute), CompleteTopSet: true}
	for i := range rows {
		key := fmt.Sprintf("group-%03d", i)
		window.Rows = append(window.Rows, RankedFlowField{TenantID: tenant, Key: key, Rank: i + 1, Value: fmt.Sprint(1000 - i), Citation: "replay:" + key})
	}
	return window
}
