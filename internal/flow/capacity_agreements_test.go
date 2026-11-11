// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func capacityAgreementFixture() CapacityAgreementDefinition {
	return CapacityAgreementDefinition{Name: "WAN contract", Reference: "operator-recorded terms", ValidFrom: "2026-11-01T05:45:00.123456789+05:45", Target: CapacityTarget{Kind: "interface", ContextID: "22222222-2222-4222-8222-222222222222", InterfaceID: "33333333-3333-4333-8333-333333333333"}, BillingDay: 31, Timezone: "Asia/Kathmandu", Direction: string(capacityBillingMaxPercentiles), Currency: "USD", CommitBPS: "1000000000", UnitBPS: "1000000", UnitPrice: "1.250000000000000001"}
}

func TestCapacityAgreementDefinitionKeepsFullTargetsTermsPrecisionAndTenantBoundary(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		input := capacityAgreementFixture()
		got, err := NormalizeCapacityAgreement(ctx, input, 8<<20, 8<<20)
		if err != nil || got.Target != input.Target || got.CommitBPS != input.CommitBPS || got.UnitPrice != input.UnitPrice || got.ValidFrom != "2026-11-01T00:00:00.123456789Z" || got.BillingDay != 31 || got.Direction != input.Direction {
			t.Fatal("operator terms or nanosecond effective date were narrowed", got, err)
		}
		input.Target = CapacityTarget{Kind: "circuit", TagID: "44444444-4444-4444-8444-444444444444", TagValue: strings.Repeat("線", 24000)}
		input.UnitPrice = "-0.000000000000000001"
		got, err = NormalizeCapacityAgreement(ctx, input, 32<<20, 32<<20)
		if err != nil || got.Target != input.Target || got.UnitPrice != input.UnitPrice {
			t.Fatal("complete circuit value or recorded credit rate was shortened", err)
		}
	}
	if _, err := NormalizeCapacityAgreement(t.Context(), capacityAgreementFixture(), 8<<20, 8<<20); err == nil {
		t.Fatal("agreement normalization preceded its tenant boundary")
	}
}
