// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestExplorerClickHouseRealPlanBatchCostAndTenantBoundary(t *testing.T) {
	store := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = store.Close() })
	red := fmt.Sprintf("probectl-qa-beta-report-batch-%d", time.Now().UnixNano())
	blue := red + "-blue"
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	first := explorerFixtureRow(red)
	first.BytesScaled, first.Protocol = 9007199254740993, "TCP"
	foreign := first
	foreign.TenantID, foreign.Protocol, foreign.BytesScaled = blue, "UDP", 9007199254740994
	if err := store.Insert(t.Context(), []Row{first, foreign}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: first.TS.Add(-time.Minute), To: first.TS.Add(time.Minute), View: "table", DataSeries: "raw", GroupBy: []string{"protocol"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	for _, lane := range []struct{ tenant, protocol, exact string }{{red, "TCP", "9007199254740993"}, {blue, "UDP", "9007199254740994"}} {
		t.Run(lane.protocol, func(t *testing.T) {
			budget := DefaultExplorerBudget()
			if err := AttachExplorerBudget(store, budget); err != nil {
				t.Fatal(err)
			}
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(lane.tenant))
			batch, err := NewPlanBatch(ctx, store, lane.tenant, 2)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(batch.Close)
			check := func(result PlanResult, err error) {
				t.Helper()
				if err != nil || len(result.Rows) != 1 || result.Rows[0].Group["protocol"] != lane.protocol || result.Totals["bytes:total"] != lane.exact || result.Coverage == nil || !result.Coverage.CompleteInputs || result.Source != "raw" {
					t.Fatal("real batch lost complete same-tenant source values", err)
				}
			}
			check(batch.ExplorePlan(PlanQuery{TenantID: lane.tenant, Plan: plan}))
			used := budget.ReadBytes - batch.readBytes
			if used <= 0 || used > budget.ReadBytes/2 {
				t.Fatal("real source did not provide bounded read receipts")
			}
			check(batch.ExplorePlan(PlanQuery{TenantID: lane.tenant, Plan: plan}))
			batch.Close()
			budget.ReadBytes = used*2 - 1
			if err := AttachExplorerBudget(store, budget); err != nil {
				t.Fatal(err)
			}
			narrow, err := NewPlanBatch(ctx, store, lane.tenant, 2)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(narrow.Close)
			check(narrow.ExplorePlan(PlanQuery{TenantID: lane.tenant, Plan: plan}))
			result, err := narrow.ExplorePlan(PlanQuery{TenantID: lane.tenant, Plan: plan})
			if !errors.Is(err, ErrExplorerBudget) || len(result.Rows) != 0 {
				t.Fatal("real repeated source reset the whole-batch read budget", err)
			}
			t.Logf("actual scoped batch: one_plan_read_bytes=%d shared_limit=%d second_plan_refused=true", used, budget.ReadBytes)
		})
	}
}
