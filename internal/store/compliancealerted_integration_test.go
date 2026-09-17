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

// DPR-073: exactly one claim wins per tenant × policy × rule; a second replica
// (or a replay) loses; tenants never see each other's claims.
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
	claim := func(tenant string) (won bool) {
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			won, err = (ComplianceAlerted{}).Claim(ctx, sc, "pci-segmentation", "corp-to-cde")
			return err
		})
		return won
	}
	if !claim(a.ID) {
		t.Fatal("first claim must win")
	}
	if claim(a.ID) {
		t.Fatal("second claim (another replica, or a replay) must lose")
	}
	if !claim(b.ID) {
		t.Fatal("another tenant's identical pair is its own claim (isolation)")
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		return (ComplianceAlerted{}).Release(ctx, sc, "pci-segmentation", "corp-to-cde")
	})
	if !claim(a.ID) {
		t.Fatal("a released pair can be claimed again")
	}
	if claim(b.ID) {
		t.Fatal("releasing tenant A must not touch tenant B's claim")
	}
}
