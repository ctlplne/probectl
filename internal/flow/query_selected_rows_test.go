// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"testing"
	"time"
)

func TestSelectedDetailReachUsesRepresentationRatherThanFormerQuota(t *testing.T) {
	for _, view := range []string{"table", "line", "bar", "timeline", "matrix"} {
		for _, rows := range []int{351, 50000, 50001, 2147483647} {
			plan := QueryPlan{View: view, GroupBy: []string{"src_addr"}, RowLimit: rows, PageSize: 1}
			if view == "matrix" {
				plan.MatrixWith = []string{"dst_addr"}
			}
			got, err := NormalizeQueryPlan(plan, time.Now())
			if err != nil || got.RowLimit != rows {
				t.Fatalf("selected detail reach refused or clamped view=%s rows=%d: %v", view, rows, err)
			}
		}
	}
	for _, rows := range []int{-1, 2147483648} {
		if _, err := NormalizeQueryPlan(QueryPlan{RowLimit: rows}, time.Now()); err == nil {
			t.Fatal("invalid selected row representation accepted", rows)
		}
	}
	got, err := NormalizeQueryPlan(QueryPlan{}, time.Now())
	if err != nil || got.RowLimit != 100 {
		t.Fatal("starting detail count changed", err)
	}
}
