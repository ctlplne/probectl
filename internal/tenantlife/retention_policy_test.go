// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tenantlife

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRetentionAuditMandatoryActorAndTenantScopeBeforeStorage(t *testing.T) {
	const (
		tenantA = "00000000-0000-0000-0000-0000000000a1"
		tenantB = "00000000-0000-0000-0000-0000000000b1"
	)
	days := 14
	engine := New(nil, nil, nil, nil, nil, "", nil)
	policyA := RetentionPolicy{TenantID: tenantA, FlowRetentionDays: &days}

	if err := engine.SetRetention(context.Background(), policyA, "actor"); !errors.Is(err, tenancy.ErrNoTenant) {
		t.Fatalf("missing authoritative context error = %v, want %v", err, tenancy.ErrNoTenant)
	}

	ctxA := tenancy.WithTenant(context.Background(), tenancy.ID(tenantA))
	policyB := policyA
	policyB.TenantID = tenantB
	if err := engine.SetRetention(ctxA, policyB, "actor"); err == nil ||
		!strings.Contains(err.Error(), "does not match caller scope") {
		t.Fatalf("tenant mismatch error = %v, want fail-closed scope mismatch", err)
	}

	if err := engine.SetRetention(ctxA, policyA, " \t\n "); err == nil ||
		!strings.Contains(err.Error(), "audit actor is required") {
		t.Fatalf("blank actor error = %v, want mandatory audit identity", err)
	}

	oversized := strings.Repeat("a", maxRetentionAuditActorBytes+1)
	if err := engine.SetRetention(ctxA, policyA, oversized); err == nil ||
		!strings.Contains(err.Error(), "audit actor exceeds") {
		t.Fatalf("oversized actor error = %v, want bounded audit identity", err)
	}
}

func TestTenantAuditRetentionBoundRejectsLooserPolicyBeforeStorage(t *testing.T) {
	const tenantID = "00000000-0000-0000-0000-0000000000a1"
	maximum := 365 * 24 * time.Hour
	tooLong := 366
	engine := New(nil, nil, nil, nil, nil, "", nil).
		WithAuditRetentionMaximum(maximum)

	err := engine.SetRetention(
		tenancy.WithTenant(context.Background(), tenancy.ID(tenantID)),
		RetentionPolicy{TenantID: tenantID, AuditRetentionDays: &tooLong},
		"actor",
	)
	if !errors.Is(err, ErrAuditRetentionExceedsMaximum) {
		t.Fatalf("above-maximum audit retention error = %v, want %v", err, ErrAuditRetentionExceedsMaximum)
	}

	thirty := 30
	if err := validateRetentionPolicy(
		RetentionPolicy{TenantID: tenantID, AuditRetentionDays: &thirty},
		maximum,
	); err != nil {
		t.Fatalf("30-day tenant tightening rejected under 365-day maximum: %v", err)
	}
	if err := validateRetentionPolicy(
		RetentionPolicy{TenantID: tenantID, AuditRetentionDays: &thirty},
		0,
	); err != nil {
		t.Fatalf("finite tenant tightening rejected under keep-forever deployment: %v", err)
	}

	staleOversized := int(maxAuditRetentionDays + 1)
	got, err := storedAuditRetentionWindow(staleOversized, maximum)
	if err != nil || got != maximum {
		t.Fatalf(
			"stale oversized stored window = (%v, %v), want deployment clamp (%v, nil)",
			got,
			err,
			maximum,
		)
	}
	for _, legacy := range []int{0, -1} {
		got, err := storedAuditRetentionWindow(legacy, maximum)
		if err != nil || got != 0 {
			t.Fatalf(
				"legacy stored window %d = (%v, %v), want inherited (0, nil)",
				legacy,
				got,
				err,
			)
		}
	}
}
