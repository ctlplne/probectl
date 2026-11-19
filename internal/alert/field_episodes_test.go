// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestFieldEpisodeStartsOncePerCompleteWindowSequence(t *testing.T) {
	binding := QueryGroupBinding{
		TenantID: "25ebf92b-c387-451d-9e67-0b323c402a58", RuleID: "18df565b-2523-443a-b139-eab57d6c0f79",
		ViewID: "548baa36-4c4a-47a1-b7d8-7c7f48d36716", ViewVersion: "7",
	}
	binding.Condition = QueryCondition{Mode: FieldChangeCondition, Field: &flow.FieldComparisonInput{
		Version: binding.ViewVersion, Mode: "rank", Measure: "bytes:total", Cadence: "previous_period",
		PeriodSeconds: 60, TopKeys: 25, MinimumRankChange: 1, MinimumChange: "1",
	}}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(binding.TenantID))
	begin := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	budget := QueryGroupBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20}
	change := flow.FieldChange{Key: strings.Repeat("ab", 32), Kind: "entered_top_set",
		Group: map[string]string{"src_addr": "192.0.2.50"},
		After: &flow.FieldObservation{Rank: 1, Value: "9007199254740993", Citation: "trusted-field-observation"}}
	when := func(minute int, changes []flow.FieldChange) flow.FieldComparison {
		end := begin.Add(time.Duration(minute) * time.Minute)
		return flow.FieldComparison{
			ViewID: binding.ViewID, Version: binding.ViewVersion, TopKeys: 25,
			Mode: "rank", Measure: "bytes:total", Cadence: "previous_period",
			Before:  flow.FieldComparisonSlice{From: end.Add(-2 * time.Minute), To: end.Add(-time.Minute)},
			After:   flow.FieldComparisonSlice{From: end.Add(-time.Minute), To: end},
			Changes: changes,
		}
	}
	one, live, err := EvaluateFieldEpisodes(ctx, binding, QueryGroupState{}, when(1, []flow.FieldChange{change}), budget)
	if err != nil || len(one) != 1 || len(live.Keys) != 1 {
		t.Fatal("first completed window must start the episode", err)
	}
	replay, _, err := EvaluateFieldEpisodes(ctx, binding, QueryGroupState{}, when(1, []flow.FieldChange{change}), budget)
	if err != nil || len(replay) != 1 || replay[0].SignalID != one[0].SignalID {
		t.Fatal("retry lost the deterministic signal identity", err)
	}
	duplicates, stillLive, err := EvaluateFieldEpisodes(ctx, binding, live, when(2, []flow.FieldChange{change}), budget)
	if err != nil || len(duplicates) != 0 || len(stillLive.Keys) != 1 {
		t.Fatal("subsequent completed windows must keep the same active episode", err)
	}
	if signals, _, err := EvaluateFieldEpisodes(ctx, binding, stillLive, when(3, nil), budget); !errors.Is(err, ErrQueryGroups) || len(signals) != 0 {
		t.Fatal("unavailable evidence cleared an active episode", err)
	}
	normal, cleared, err := EvaluateFieldEpisodes(ctx, binding, stillLive, when(3, []flow.FieldChange{}), budget)
	if err != nil || len(normal) != 0 || len(cleared.Keys) != 0 {
		t.Fatal("the next complete normal window must clear the episode", err)
	}
	second, _, err := EvaluateFieldEpisodes(ctx, binding, cleared, when(4, []flow.FieldChange{change}), budget)
	if err != nil || len(second) != 1 || second[0].SignalID == one[0].SignalID || second[0].GroupKey != one[0].GroupKey {
		t.Fatal("a later recurrence must have a new signal and the same group", err)
	}
	sibling := tenancy.WithTenant(ctx, tenancy.ID("aada3cf5-de40-4ac5-ae6d-c7bea50fd2dd"))
	if signals, _, err := EvaluateFieldEpisodes(sibling, binding, cleared, when(4, []flow.FieldChange{change}), budget); !errors.Is(err, tenancy.ErrNoTenant) || len(signals) != 0 {
		t.Fatal("a sibling tenant advanced a field episode", err)
	}
}
