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

func TestSeasonalFlowWindowPlanUsesRealClickHouseTenantReader(t *testing.T) {
	store := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = store.Close() })
	red := fmt.Sprintf("probectl-qa-beta-seasonal-periods-%d", time.Now().UnixNano())
	blue := red + "-blue"
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
	})
	plan, ends := checkSeasonalFlowWindowPlan(t, store, red, blue)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(red))
	budget := ExplorerQueryBudget(store)
	query := PlanQuery{TenantID: red, Plan: plan}
	var vocabulary flow.QueryVocabulary
	span, clocks, err := seasonalFlowPlan(ctx, query, ends, vocabulary, budget)
	if err != nil {
		t.Fatal(err)
	}
	target, err := store.route(ctx, red)
	if err != nil {
		t.Fatal(err)
	}
	lane, err := store.readLane(target, red)
	if err != nil {
		t.Fatal(err)
	}
	table, err := tableFor(target)
	if err != nil {
		t.Fatal(err)
	}
	limited, err := buildSeasonalFlowSQL(ctx, budget, query, span, table, nil, vocabulary, clocks, 1)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.explorerQueryRows(ctx, target, lane, red, limited.sql, limited.params, limited.clocks...)
	if !errors.Is(err, ErrExplorerBudget) || len(rows) != 0 {
		t.Fatal("overlapping memberships were not refused before returning groups", err)
	}
}
