// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/store"
)

func TestDependencyReachabilityRequiresCurrentSourceNotRawClaims(t *testing.T) {
	node := alert.DependencyNodeInput{AgentID: "current-agent"}
	rule := alert.Rule{Metric: "probectl_probe_success", Comparison: alert.EQ, Threshold: 0}
	attempt := alert.DependencyAttempt{Alert: alert.Alert{Value: 0, Labels: map[string]string{"agent_id": node.AgentID}}}
	for _, state := range []string{"up", "unknown", ""} {
		if dependencyReachabilityAttempt(rule, attempt, node, store.ICMPHealth{State: state}) {
			t.Fatal("raw numeric failure manufactured current echo loss", state)
		}
	}
	if !dependencyReachabilityAttempt(rule, attempt, node, store.ICMPHealth{State: "down"}) {
		t.Fatal("a current complete source could not establish the reachability symptom")
	}
	for _, field := range []string{"agent", "missing-agent", "metric", "comparison", "threshold", "value"} {
		changedRule, changedAttempt := rule, attempt
		changedAttempt.Alert.Labels = map[string]string{"agent_id": node.AgentID}
		switch field {
		case "agent":
			changedAttempt.Alert.Labels["agent_id"] = "another-agent"
		case "missing-agent":
			delete(changedAttempt.Alert.Labels, "agent_id")
		case "metric":
			changedRule.Metric = "cpu_usage_percent"
		case "comparison":
			changedRule.Comparison = alert.GT
		case "threshold":
			changedRule.Threshold = 1
		case "value":
			changedAttempt.Alert.Value = 1
		}
		if dependencyReachabilityAttempt(changedRule, changedAttempt, node, store.ICMPHealth{State: "down"}) {
			t.Fatal("independent or foreign-source symptom inherited a reachability hold", field)
		}
	}
}
