// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type queryRuleSourceForTest struct {
	read RuleMetricRead
	err  error
}

func (*queryRuleSourceForTest) Current(context.Context, string, map[string]string) ([]Sample, error) {
	return nil, errors.New("query rule must never fall back to the metric source")
}

func (s *queryRuleSourceForTest) CurrentRule(context.Context, Rule) (RuleMetricRead, error) {
	return s.read, s.err
}

func queryEngineForTest() (*Engine, *queryRuleSourceForTest, Rule, Sample) {
	binding, snapshot, _ := queryGroupsForTest()
	rule := Rule{ID: binding.RuleID, TenantID: binding.TenantID, Name: "Saved query", Enabled: true, Metric: QueryMetric, Type: Threshold, Comparison: GTE, Threshold: 1, ForN: 1, Severity: SeverityWarning}
	selection := &QuerySelection{TenantID: rule.TenantID, RuleID: rule.ID, Binding: strings.Repeat("a", 64), At: snapshot.At, Complete: true}
	sample := Sample{Labels: map[string]string{"query_view_id": binding.ViewID, "query_group": strings.Repeat("b", 64)}, Value: 1}
	source := &queryRuleSourceForTest{read: RuleMetricRead{Samples: []Sample{sample}, QuerySelection: selection}}
	return NewEngine(source, nil, discard()), source, rule, sample
}

func TestSavedQueryAlertEngineFiresOnceAndResolvesOnlyACompleteDeparture(t *testing.T) {
	engine, source, rule, sample := queryEngineForTest()
	for i := range 2 {
		acted, err := engine.Evaluate(t.Context(), rule)
		want := 1
		if i == 1 {
			want = 0
		}
		if err != nil || len(acted) != want || len(acted) == 1 && (acted[0].State != StateFiring || acted[0].Reason != "saved-query condition met") {
			t.Fatal("query group did not fire exactly once", acted, err)
		}
	}
	source.read.Samples = nil
	source.read.QuerySelection.Complete = false
	if acted, err := engine.Evaluate(t.Context(), rule); err == nil || len(acted) != 0 || !engine.states[stateKey(rule.ID, sample.Labels)].firing {
		t.Fatal("partial read resolved a firing group", acted, err)
	}
	source.read.QuerySelection.Complete = true
	acted, err := engine.Evaluate(t.Context(), rule)
	if err != nil || len(acted) != 1 || acted[0].State != StateResolved || len(engine.states) != 0 {
		t.Fatal("complete group departure did not resolve and release its state", acted, len(engine.states), err)
	}
	if acted, err := engine.Evaluate(t.Context(), rule); err != nil || len(acted) != 0 {
		t.Fatal("complete empty population repeated a resolution", acted, err)
	}
}

func TestSavedQueryAlertEngineRestoresNotificationAndResolvesAcrossRestart(t *testing.T) {
	for _, current := range []string{"present", "nonbreaching", "absent"} {
		t.Run(current, func(t *testing.T) {
			engine, source, rule, sample := queryEngineForTest()
			at := time.Now().UTC().Add(-time.Minute)
			key := stateKey(rule.ID, sample.Labels)
			engine.RestoreNotifications(map[string]NotifyState{key: {FiringSince: at, LastNotified: at}})
			if current == "absent" {
				source.read.Samples = nil
			} else if current == "nonbreaching" {
				source.read.Samples[0].Value = 0
			}
			acted, err := engine.Evaluate(t.Context(), rule)
			if err != nil {
				t.Fatal(err)
			}
			if current == "present" {
				if len(acted) != 0 || !engine.states[key].firing || !engine.states[key].since.Equal(at) {
					t.Fatal("restart duplicated the still-firing episode", acted)
				}
			} else if len(acted) != 1 || acted[0].State != StateResolved {
				t.Fatal("restart lost a complete resolution", acted)
			}
			if len(engine.restoredNotify) != 0 {
				t.Fatal("completed current source did not consume its restored episode")
			}
		})
	}
}

func TestSavedQueryAlertEngineRejectsForeignSelectionWithoutEffects(t *testing.T) {
	for _, mutate := range []func(*RuleMetricRead){
		func(r *RuleMetricRead) { r.QuerySelection.TenantID = "44444444-4444-4444-8444-444444444444" },
		func(r *RuleMetricRead) { r.QuerySelection.RuleID = "44444444-4444-4444-8444-444444444444" },
		func(r *RuleMetricRead) { r.QuerySelection = nil },
		func(r *RuleMetricRead) { r.Samples[0].Labels["query_group"] = "not-a-complete-group-key" },
		func(r *RuleMetricRead) { r.Samples[0].Value = 2 },
	} {
		engine, source, rule, _ := queryEngineForTest()
		mutate(&source.read)
		if acted, err := engine.Evaluate(t.Context(), rule); err == nil || len(acted) != 0 || len(engine.states) != 0 {
			t.Fatal("invalid/foreign source changed a query episode", acted, err)
		}
	}
}

func TestSavedQueryAlertNotDueDoesNotInventAHealthyRead(t *testing.T) {
	engine, source, rule, sample := queryEngineForTest()
	if acted, err := engine.Evaluate(t.Context(), rule); err != nil || len(acted) != 1 {
		t.Fatal("initial query condition did not fire", acted, err)
	}
	source.read = RuleMetricRead{Skip: true}
	if acted, err := engine.Evaluate(t.Context(), rule); err != nil || len(acted) != 0 || !engine.states[stateKey(rule.ID, sample.Labels)].firing {
		t.Fatal("not-due tick cleared the last known firing condition", acted, err)
	}
	source.read.Samples = []Sample{sample}
	if acted, err := engine.Evaluate(t.Context(), rule); err == nil || len(acted) != 0 {
		t.Fatal("a skipped query smuggled unverified samples", acted, err)
	}
}

func TestSavedQueryOpaqueGroupHandleRejectsUnboundedOrAmbiguousSyntax(t *testing.T) {
	if !ValidQueryGroupKey(strings.Repeat("a", 64)) {
		t.Fatal("canonical opaque handle was refused")
	}
	for _, key := range []string{"", strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 65), strings.Repeat("a", 2<<20)} {
		if ValidQueryGroupKey(key) {
			t.Fatal("invalid group handle was accepted")
		}
	}
}
