// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func queryGroupsForTest() (QueryGroupBinding, QueryGroupSnapshot, QueryGroupBudget) {
	binding := QueryGroupBinding{TenantID: "11111111-1111-4111-8111-111111111111", RuleID: "22222222-2222-4222-8222-222222222222", ViewID: "33333333-3333-4333-8333-333333333333", ViewVersion: "1", Condition: QueryCondition{Mode: "threshold", Metric: "bytes:total", Comparison: GT, Threshold: "18446744073709551616"}}
	snapshot := QueryGroupSnapshot{TenantID: binding.TenantID, ViewID: binding.ViewID, ViewVersion: binding.ViewVersion, At: time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC), Complete: true}
	return binding, snapshot, QueryGroupBudget{MemoryBytes: 256 << 20, WorkUnits: 1 << 30}
}

func TestSavedQueryAlertGroupsCompareWideValuesAndKeepCompletePopulation(t *testing.T) {
	binding, snapshot, budget := queryGroupsForTest()
	metrics := []flow.QueryMetric{{Measure: "bytes", Calculation: "total"}}
	if err := binding.Condition.Validate(metrics); err != nil {
		t.Fatal(err)
	}
	// The adjacent integers round to the same float64. Every selected group,
	// beyond the old 50,000 table size, must still get its exact comparison.
	for i := range 50001 {
		value := "18446744073709551616"
		if i%2 == 0 {
			value = "18446744073709551617"
		}
		snapshot.Groups = append(snapshot.Groups, QueryGroup{Dimensions: map[string]string{"src_asn": strconv.Itoa(i)}, Value: value})
	}
	decisions, state, err := EvaluateQueryGroups(tenancy.WithTenant(t.Context(), tenancy.ID(binding.TenantID)), binding, snapshot, QueryGroupState{}, budget)
	if err != nil || len(decisions) != 50001 || len(state.Keys) != 50001 {
		t.Fatal("complete selected group population lost", len(decisions), len(state.Keys), err)
	}
	breached := 0
	for _, decision := range decisions {
		id, err := strconv.Atoi(decision.Dimensions["src_asn"])
		if err != nil || !decision.Present || decision.Breached != (id%2 == 0) {
			t.Fatal("wide exact threshold was rounded", decision, err)
		}
		if decision.Breached {
			breached++
		}
	}
	if breached != 25001 {
		t.Fatal("wrong exact crossing population", breached)
	}
	snapshot.At = snapshot.At.Add(time.Minute)
	snapshot.Groups = nil
	decisions, next, err := EvaluateQueryGroups(tenancy.WithTenant(t.Context(), tenancy.ID(binding.TenantID)), binding, snapshot, state, budget)
	if err != nil || len(decisions) != 50001 || len(next.Keys) != 0 {
		t.Fatal("complete empty selection did not clear previous groups", err)
	}
	for _, decision := range decisions {
		if decision.Present || decision.Breached || decision.Value != "" {
			t.Fatal("absence invented a zero measurement or retained a breach", decision)
		}
	}
}

func TestSavedQueryAlertNovelGroupsWarmHoldAndClearOnCompleteSelection(t *testing.T) {
	binding, snapshot, budget := queryGroupsForTest()
	binding.Condition = QueryCondition{Mode: "new_group"}
	if err := binding.Condition.Validate(nil); err != nil {
		t.Fatal(err)
	}
	first := QueryGroup{Dimensions: map[string]string{"src_asn": "64512"}}
	added := QueryGroup{Dimensions: map[string]string{"src_asn": "64513"}}
	snapshot.Groups = []QueryGroup{first}
	decisions, state, err := EvaluateQueryGroups(tenancy.WithTenant(t.Context(), tenancy.ID(binding.TenantID)), binding, snapshot, QueryGroupState{}, budget)
	if err != nil || len(decisions) != 1 || decisions[0].Breached || !state.Initialized {
		t.Fatal("first complete selection did not warm", decisions, err)
	}
	for range 2 {
		snapshot.At = snapshot.At.Add(time.Minute)
		snapshot.Groups = []QueryGroup{first, added}
		decisions, state, err = EvaluateQueryGroups(tenancy.WithTenant(t.Context(), tenancy.ID(binding.TenantID)), binding, snapshot, state, budget)
		if err != nil || len(decisions) != 2 || len(state.Novel) != 1 {
			t.Fatal("new top-set member lost its firing episode", decisions, err)
		}
		for _, decision := range decisions {
			if decision.Breached != (decision.Dimensions["src_asn"] == "64513") {
				t.Fatal("baseline member fired or novel member cleared while present", decision)
			}
		}
	}
	snapshot.At = snapshot.At.Add(time.Minute)
	snapshot.Groups = []QueryGroup{first}
	decisions, state, err = EvaluateQueryGroups(tenancy.WithTenant(t.Context(), tenancy.ID(binding.TenantID)), binding, snapshot, state, budget)
	if err != nil || len(decisions) != 2 || len(state.Novel) != 0 {
		t.Fatal("departed novel member did not clear", decisions, err)
	}
	for _, decision := range decisions {
		if decision.Breached {
			t.Fatal("departed member is still firing", decision)
		}
	}
}

func TestSavedQueryAlertGroupsBindBothTenantsAndFramedDimensions(t *testing.T) {
	binding, snapshot, budget := queryGroupsForTest()
	snapshot.Groups = []QueryGroup{{Dimensions: map[string]string{"a": "b;c=d"}, Value: "1"}, {Dimensions: map[string]string{"a": "b", "c": "d"}, Value: "1"}, {Dimensions: map[string]string{"a": "☃/東京"}, Value: "1"}}
	first, state, err := EvaluateQueryGroups(tenancy.WithTenant(t.Context(), tenancy.ID(binding.TenantID)), binding, snapshot, QueryGroupState{}, budget)
	if err != nil || len(first) != 3 || first[0].Key == first[1].Key || first[1].Key == first[2].Key {
		t.Fatal("framed dimensions collided", first, err)
	}
	foreign := binding
	foreign.TenantID = "44444444-4444-4444-8444-444444444444"
	foreignSnapshot := snapshot
	foreignSnapshot.TenantID = foreign.TenantID
	second, _, err := EvaluateQueryGroups(tenancy.WithTenant(t.Context(), tenancy.ID(foreign.TenantID)), foreign, foreignSnapshot, QueryGroupState{}, budget)
	if err != nil {
		t.Fatal(err)
	}
	for _, own := range first {
		for _, other := range second {
			if own.Key == other.Key {
				t.Fatal("tenant states share a group identity")
			}
		}
	}
	foreignSnapshot.At = snapshot.At.Add(time.Minute)
	if got, next, err := EvaluateQueryGroups(tenancy.WithTenant(t.Context(), tenancy.ID(foreign.TenantID)), foreign, foreignSnapshot, state, budget); err == nil || got != nil || !reflect.DeepEqual(next, QueryGroupState{}) {
		t.Fatal("foreign tenant state produced transitions", got, next, err)
	}
	if got, _, err := EvaluateQueryGroups(tenancy.WithTenant(t.Context(), tenancy.ID(binding.TenantID)), binding, foreignSnapshot, QueryGroupState{}, budget); err == nil || got != nil {
		t.Fatal("foreign query output reached this tenant's alert", got, err)
	}
	if got, _, err := EvaluateQueryGroups(t.Context(), binding, snapshot, QueryGroupState{}, budget); !errors.Is(err, tenancy.ErrNoTenant) || got != nil {
		t.Fatal("missing tenant context reached query evaluation", got, err)
	}
	if got, _, err := EvaluateQueryGroups(tenancy.WithTenant(t.Context(), tenancy.ID(foreign.TenantID)), binding, snapshot, QueryGroupState{}, budget); err == nil || got != nil {
		t.Fatal("foreign tenant context reached query evaluation", got, err)
	}
	// The returned explanation owns its map; later source reuse cannot rewrite
	// a decision that is waiting for atomic publication.
	snapshot.Groups[0].Dimensions["a"] = "changed"
	for _, decision := range first {
		if decision.Dimensions["a"] == "changed" {
			t.Fatal("mutable source map rewrote an evaluated group")
		}
	}
}

func TestSavedQueryAlertIncompleteOrRefusedReadNeverProducesPartialTransitions(t *testing.T) {
	binding, snapshot, budget := queryGroupsForTest()
	snapshot.Groups = []QueryGroup{{Dimensions: map[string]string{"src_asn": "64512"}, Value: "18446744073709551617"}}
	_, state, err := EvaluateQueryGroups(tenancy.WithTenant(t.Context(), tenancy.ID(binding.TenantID)), binding, snapshot, QueryGroupState{}, budget)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.At = snapshot.At.Add(time.Minute)
	for _, scenario := range []string{"partial", "stale", "revision", "duplicate", "invalid decimal", "memory", "work", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			current, currentBudget := snapshot, budget
			ctx, cancel := context.WithCancel(tenancy.WithTenant(t.Context(), tenancy.ID(binding.TenantID)))
			defer cancel()
			switch scenario {
			case "partial":
				current.Complete = false
			case "stale":
				current.At = state.At
			case "revision":
				current.ViewVersion = "2"
			case "duplicate":
				current.Groups = append(append([]QueryGroup{}, snapshot.Groups...), snapshot.Groups[0])
			case "invalid decimal":
				current.Groups = []QueryGroup{snapshot.Groups[0], {Dimensions: map[string]string{"src_asn": "64513"}, Value: "1e9"}}
			case "memory":
				currentBudget.MemoryBytes = 4096
			case "work":
				currentBudget.WorkUnits = 4800
			case "cancelled":
				cancel()
			}
			decisions, next, err := EvaluateQueryGroups(ctx, binding, current, state, currentBudget)
			if err == nil || decisions != nil || !reflect.DeepEqual(next, QueryGroupState{}) {
				t.Fatal("incomplete/refused read changed state or returned a partial result", decisions, next, err)
			}
			if scenario == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation was lost", err)
			}
		})
	}
}
