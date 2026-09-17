// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// DPR-073: exactly one claim wins per tenant × policy × rule × period; a
// second replica (or a replay) loses; tenants never see each other's claims.
// DPR-110: the next period re-arms the pair.
func TestComplianceAlertedClaimIsOnceOnlyAndIsolated(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "seg-a-"+suffix, "seg-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "seg-b-"+suffix, "seg-b")
	if err != nil {
		t.Fatal(err)
	}
	claim := func(tenant, period string) (won bool) {
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			won, err = (ComplianceAlerted{}).Claim(ctx, sc, "pci-segmentation", "corp-to-cde", period)
			return err
		})
		return won
	}
	today, tomorrow := "2026-09-17T00:00:00Z", "2026-09-18T00:00:00Z"
	if !claim(a.ID, today) {
		t.Fatal("first claim must win")
	}
	if claim(a.ID, today) {
		t.Fatal("second claim (another replica, or a replay) must lose")
	}
	if !claim(b.ID, today) {
		t.Fatal("another tenant's identical pair is its own claim (isolation)")
	}
	// DPR-110: the next window re-arms the pair, so a violation that returns
	// after remediation is reported instead of meeting a permanently closed
	// gate — and it re-arms per tenant, not globally.
	if !claim(a.ID, tomorrow) {
		t.Fatal("the next period must re-arm the pair")
	}
	if claim(a.ID, tomorrow) {
		t.Fatal("the new period is itself once-only")
	}
	if !claim(b.ID, tomorrow) {
		t.Fatal("tenant B's re-arm is its own claim")
	}
}
