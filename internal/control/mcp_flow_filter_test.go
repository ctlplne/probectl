// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

// TestQueryFlowEventsHonorsSrcFilter is the AI-07 regression. query_flows
// advertises a `src` (and `dst`) filter, but the backend ignored it — it chose
// a grouping and only ever filtered on `target`, so a query with src=X returned
// every top-talker regardless of source. Now src/dst actually filter the rows.
func TestQueryFlowEventsHonorsSrcFilter(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	flows := flowstore.NewMemory()
	if err := flows.Insert(ctx, []flowstore.Row{
		{TenantID: "t1", Exporter: "e", TS: now.Add(-time.Minute), SrcAddr: "10.0.0.1", DstAddr: "10.0.0.9", BytesScaled: 5000, PacketsScaled: 50},
		{TenantID: "t1", Exporter: "e", TS: now.Add(-time.Minute), SrcAddr: "10.0.0.2", DstAddr: "10.0.0.9", BytesScaled: 9000, PacketsScaled: 90},
	}); err != nil {
		t.Fatal(err)
	}
	src := changeEventsSource{flow: flows}
	rng := ai.TimeRange{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}

	rows, err := src.QueryEvents(ctx, "t1", map[string]string{"type": "flow", "src": "10.0.0.1"}, rng, 50)
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("AI-07: src=10.0.0.1 returned no rows though that source has flows")
	}
	for _, r := range rows {
		if r["target"] != "10.0.0.1" {
			t.Fatalf("AI-07: query_flows src=10.0.0.1 returned a non-matching source %v (filter ignored)", r["target"])
		}
	}
}
