// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// DPR-080: exactly one claim wins per tenant × budget × month; a second replica
// (or a replay) loses; a new month is a new claim; tenants never see each other's.
func TestCostBudgetAlertedClaimIsOnceOnlyPerMonthAndIsolated(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "cost-a-"+suffix, "cost-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "cost-b-"+suffix, "cost-b")
	if err != nil {
		t.Fatal(err)
	}
	claim := func(tenant, month string) (won bool) {
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			won, err = (CostBudgetAlerted{}).Claim(ctx, sc, "team:payments", month)
			return err
		})
		return won
	}
	if !claim(a.ID, "2026-09") {
		t.Fatal("first claim must win")
	}
	if claim(a.ID, "2026-09") {
		t.Fatal("second claim (another replica, or a replay) must lose")
	}
	if !claim(a.ID, "2026-10") {
		t.Fatal("a new month is a new claim")
	}
	if !claim(b.ID, "2026-09") {
		t.Fatal("another tenant's identical budget is its own claim (isolation)")
	}
}
