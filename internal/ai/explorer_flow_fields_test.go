// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"testing"
	"time"
)

func TestFlowExplorerStoredFieldGrammar(t *testing.T) {
	_, err := NormalizeExplorerQuery(ExplorerQuery{
		Question: "Traffic by source address and destination port", Source: ExplorerFlow,
		Dimensions: []string{"src_addr", "dst_port"}, Groupings: []string{"src_addr", "dst_port"},
		Measures: []string{"bytes", "packets", "flows"}, Limit: 25,
	}, time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("stored flow fields must be queryable: %v", err)
	}
}

func TestFlowExplorerRejectsOverBudgetRows(t *testing.T) {
	_, err := NormalizeExplorerQuery(ExplorerQuery{
		Question: "Traffic by site", Source: ExplorerFlow,
		Dimensions: []string{"src_addr"}, Measures: []string{"bps"}, Limit: 50001,
	}, time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("over-budget flow query must refuse, never silently clamp")
	}
}
