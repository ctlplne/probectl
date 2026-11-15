// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestAssessmentFlowBatchSharesRetainedMemoryWithoutCrossTenantQueries(t *testing.T) {
	store := NewMemory()
	policy := DefaultExplorerBudget()
	policy.MemoryBytes = 32 << 20
	if err := AttachExplorerBudget(store, policy); err != nil {
		t.Fatal(err)
	}
	for i, tenant := range []string{"red", "blue"} {
		row := explorerFixtureRow(tenant)
		row.BytesScaled, row.Protocol = uint64(i+1)*101, tenant
		if err := store.Insert(t.Context(), []Row{row}); err != nil {
			t.Fatal(err)
		}
	}
	reserved := policy.MemoryBytes / 2
	for i, tenant := range []string{"red", "blue"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		batch, err := NewReportPlanBatch(ctx, store, tenant, 2, reserved, 2*time.Minute, 3)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(batch.Close)
		deadline, ok := batch.Context().Deadline()
		if !ok || time.Until(deadline) < 90*time.Second {
			t.Fatal("report inherited the shorter interactive operation deadline")
		}
		if batch.budget.MemoryBytes*5+reserved > policy.MemoryBytes || batch.readBytes != policy.ReadBytes || batch.readRows != policy.ReadRows || ExplorerQueryBudget(store).MemoryBytes != policy.MemoryBytes {
			t.Fatal("retained assessment components received a second memory or source-read allowance")
		}
		at := explorerFixtureRow(tenant).TS
		plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), View: "table", GroupBy: []string{"protocol"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
		result, err := batch.ExplorePlan(PlanQuery{TenantID: tenant, Plan: plan})
		if err != nil || len(result.Rows) != 1 || result.Rows[0].Group["protocol"] != tenant || result.Totals["bytes:total"] != strconv.Itoa((i+1)*101) {
			t.Fatal("reserved workspace lost complete own values or selected foreign flow", result.Totals, err)
		}
		if _, err := batch.ExplorePlan(PlanQuery{TenantID: "foreign", Plan: plan}); !errors.Is(err, ErrNoTenant) {
			t.Fatal("reserved batch borrowed another tenant", err)
		}
		for _, invalid := range []int64{-1, policy.MemoryBytes, policy.MemoryBytes + 1} {
			if candidate, err := NewReportPlanBatch(ctx, store, tenant, 1, invalid, 2*time.Minute); err == nil || candidate != nil {
				t.Fatal("invalid retained allocation opened an unaccounted workspace")
			}
		}
		earlier := time.Now().Add(5 * time.Second)
		short, cancel := context.WithDeadline(ctx, earlier)
		bounded, err := NewReportPlanBatch(short, store, tenant, 1, 0, 2*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		until, ok := bounded.Context().Deadline()
		if !ok || !until.Equal(earlier) {
			t.Fatal("configured report deadline replaced an earlier caller bound")
		}
		bounded.Close()
		cancel()
	}
}
