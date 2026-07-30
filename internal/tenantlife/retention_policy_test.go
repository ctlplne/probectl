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

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
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
