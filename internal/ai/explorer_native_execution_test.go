// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

// This is the exact execution envelope sent by the native flow UI/API clients.
// Question is a legacy recipe label, not authority or structured query intent.
func TestExplorerNativeExecutionDoesNotRequireLegacyQuestionLabel(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	plan := flow.QueryPlan{From: now.Add(-time.Hour), To: now, GroupBy: []string{"src_addr"}, View: "table", Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	q, err := NormalizeExplorerQuery(ExplorerQuery{Source: ExplorerFlow, Flow: &plan}, now)
	if err != nil {
		t.Fatal("native UI structured execution rejected for missing nonsemantic label", err)
	}
	if q.Question == "" || q.Flow == nil || q.Flow.GroupBy[0] != "src_addr" {
		t.Fatal("canonical native label or plan lost")
	}
}

func TestExplorerQuestionStillRequiredOutsideStructuredNativeExecution(t *testing.T) {
	for _, query := range []ExplorerQuery{{Source: ExplorerFlow}, {Source: ExplorerPath}, {Source: ExplorerFlow, PlanOnly: true, Flow: &flow.QueryPlan{}}} {
		if _, err := NormalizeExplorerQuery(query, time.Now()); err == nil {
			t.Fatal("a non-native/plan-only request became an executable recipe")
		}
	}
}
