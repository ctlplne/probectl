// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"testing"
	"time"
)

func TestPathHealthAlertEngineHoldsUnprovenAndNotifiesOnceAcrossRestart(t *testing.T) {
	engine, source, rule, sample := queryEngineForTest()
	rule.Metric = PathHealthMetric
	sample.Labels = map[string]string{"path_test_id": sample.Labels["query_view_id"], "path_health_group": sample.Labels["query_group"]}
	source.read.Samples = []Sample{sample}
	selection := *source.read.QuerySelection
	for i := range 2 {
		acted, err := engine.Evaluate(t.Context(), rule)
		want := 1
		if i == 1 {
			want = 0
		}
		if err != nil || len(acted) != want || len(acted) == 1 && (acted[0].State != StateFiring || acted[0].Reason != "owned interface minimum-rate condition met") {
			t.Fatal("one owned port episode notified more than once", acted, err)
		}
	}
	key := stateKey(rule.ID, sample.Labels)
	source.read = RuleMetricRead{Skip: true}
	if acted, err := engine.Evaluate(t.Context(), rule); err != nil || len(acted) != 0 || !engine.states[key].firing {
		t.Fatal("unproven source resolved the firing episode", acted, err)
	}
	source.read = RuleMetricRead{Samples: []Sample{sample}, QuerySelection: &selection}
	for _, bad := range []RuleMetricRead{
		{Samples: []Sample{sample}},
		{QuerySelection: &selection},
		{Samples: []Sample{sample}, Skip: true},
	} {
		source.read = bad
		if acted, err := engine.Evaluate(t.Context(), rule); err == nil || len(acted) != 0 || !engine.states[key].firing {
			t.Fatal("partial or malformed selection advanced an episode", acted, err)
		}
	}
	source.read = RuleMetricRead{Samples: []Sample{sample}, QuerySelection: &selection}
	source.read.QuerySelection.TenantID = "71111111-1111-4111-8111-111111111111"
	if acted, err := engine.Evaluate(t.Context(), rule); err == nil || len(acted) != 0 {
		t.Fatal("foreign tenant selection advanced the episode", acted, err)
	}
	source.read.QuerySelection.TenantID = rule.TenantID
	restarted := NewEngine(source, nil, discard())
	at := time.Now().UTC().Add(-time.Minute)
	restarted.RestoreNotifications(map[string]NotifyState{key: {FiringSince: at, LastNotified: at}})
	if acted, err := restarted.Evaluate(t.Context(), rule); err != nil || len(acted) != 0 || !restarted.states[key].firing || !restarted.states[key].since.Equal(at) {
		t.Fatal("restart duplicated the notified owned-port episode", acted, err)
	}
	source.read.Samples[0].Value = 0
	if acted, err := restarted.Evaluate(t.Context(), rule); err != nil || len(acted) != 1 || acted[0].State != StateResolved {
		t.Fatal("complete current recovery did not resolve the restored episode", acted, err)
	}
	if acted, err := restarted.Evaluate(t.Context(), rule); err != nil || len(acted) != 0 {
		t.Fatal("complete current recovery notified repeatedly", acted, err)
	}
}
