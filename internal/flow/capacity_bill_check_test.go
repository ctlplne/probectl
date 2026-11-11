// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestCapacityBillCheckKeepsRecordedCommitRateWideFractionsAndCurrency(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		contract := capacityBillingContract{tenant: tenant, currency: "USD", commitBPS: "1000000000", unitBPS: "1000000", unitPrice: "1.25", invoiced: "3750.01"}
		measured := capacityBillingPercentile{tenant: tenant, from: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), to: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC), numerator: "3000000000", denominator: "1", expected: 8640, observed: 8640, rank: 8208, complete: true}
		check, err := capacityCheckBill(ctx, contract, measured, 8<<20, 8<<20)
		if err != nil || !check.complete || check.tenant != tenant || check.currency != "USD" || check.overageNumerator != "2000000000" || check.overageDenominator != "1" || check.chargeNumerator != "3750" || check.chargeDenominator != "1" || !check.invoiceCompared || check.invoiceDifferenceNumerator != "1" || check.invoiceDifferenceDenominator != "100" {
			t.Fatal("recorded agreement bill check rounded, inferred a rate or lost tenant", check, err)
		}
		measured.numerator = "0"
		check, err = capacityCheckBill(ctx, contract, measured, 8<<20, 8<<20)
		if err != nil || check.overageNumerator != "0" || check.billableNumerator != "1000000000" || check.chargeNumerator != "1250" {
			t.Fatal("observed zero ignored the recorded commit floor", check, err)
		}
		contract.commitBPS, contract.unitBPS, contract.unitPrice, contract.invoiced = "0", "1", "0.000000000000000001", ""
		measured.numerator, measured.denominator = "18446744073709551617", "3"
		check, err = capacityCheckBill(ctx, contract, measured, 8<<20, 8<<20)
		if err != nil || check.chargeNumerator != "18446744073709551617" || check.chargeDenominator != "3000000000000000000" || check.invoiceCompared {
			t.Fatal("wide fractional usage or recorded decimal precision was lost", check, err)
		}
		contract.commitBPS, contract.unitBPS, contract.unitPrice, contract.invoiced = "1000000000", "1000000", "-1.25", "-1250.01"
		measured.numerator, measured.denominator = "0", "1"
		check, err = capacityCheckBill(ctx, contract, measured, 8<<20, 8<<20)
		if err != nil || check.chargeNumerator != "-1250" || check.invoiceDifferenceNumerator != "-1" || check.invoiceDifferenceDenominator != "100" {
			t.Fatal("recorded credit rates or invoices were narrowed to positive charges", check, err)
		}
	}
}

func TestCapacityBillCheckWithholdsIncompletePeriodsAndForeignAgreements(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	contract := capacityBillingContract{tenant: "red", currency: "USD", commitBPS: "1000", unitBPS: "1000", unitPrice: "2.50"}
	partial := capacityBillingPercentile{tenant: "red", from: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), to: time.Date(2026, 11, 1, 1, 40, 0, 0, time.UTC), expected: 20, observed: 19, missing: 1}
	check, err := capacityCheckBill(ctx, contract, partial, 8<<20, 8<<20)
	if err != nil || check.complete || check.reason != "billing_period_incomplete" || check.chargeNumerator != "" || check.overageNumerator != "" {
		t.Fatal("missing samples became zero or a partial-period bill", check, err)
	}
	contract.tenant = "blue"
	if check, err := capacityCheckBill(ctx, contract, partial, 8<<20, 8<<20); err == nil || !reflect.DeepEqual(check, capacityBillCheck{}) {
		t.Fatal("bill check consumed another tenant's contract", check, err)
	}
	contract.tenant = "red"
	partial.tenant = "blue"
	if check, err := capacityCheckBill(ctx, contract, partial, 8<<20, 8<<20); err == nil || !reflect.DeepEqual(check, capacityBillCheck{}) {
		t.Fatal("bill check consumed another tenant's measurements", check, err)
	}
}
