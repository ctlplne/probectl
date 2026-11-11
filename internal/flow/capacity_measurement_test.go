// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestCapacityMeasuredCounterCircuitPercentileAndBillKeepExactFacts(t *testing.T) {
	ctx, source, window, points := capacitySourceTestInput()
	first, err := MeasureCapacityCounterMember(ctx, source, window, points)
	if err != nil {
		t.Fatal(err)
	}
	otherSource := source
	otherSource.InterfaceID = uuid.NewString()
	second, err := MeasureCapacityCounterMember(ctx, otherSource, window, points)
	if err != nil {
		t.Fatal(err)
	}
	measured, err := CalculateCapacityMeasuredP95(ctx, window, "out", []CapacityMeasuredMember{first, second})
	if err != nil || !measured.Result().Complete || measured.Result().BPSNumerator != "3200" || measured.Result().BPSDenominator != "1" || measured.Result().ObservedSamples != 2 {
		t.Fatal("original member rates did not reach exact circuit percentile", measured.Result(), err)
	}
	terms := CapacityAgreementDefinition{Direction: "out", Currency: "USD", CommitBPS: "1000", UnitBPS: "1000", UnitPrice: "0.250000000000000001"}
	bill, err := CheckCapacityMeasuredBill(ctx, terms, measured, "0.8000000000000000032", window.MemoryBytes, window.WorkUnits)
	if err != nil || !bill.Complete || bill.OverageNumerator != "2200" || bill.OverageDenominator != "1" ||
		bill.ChargeNumerator != "250000000000000001" || bill.ChargeDenominator != "312500000000000000" || !bill.InvoiceCompared || bill.InvoiceDifferenceNumerator != "0" {
		t.Fatal("source-to-bill calculation rounded the exact operator terms", bill, err)
	}
	if result, err := CalculateCapacityMeasuredP95(ctx, window, "out", []CapacityMeasuredMember{first, first}); err == nil || !reflect.DeepEqual(result, CapacityMeasuredPercentile{}) {
		t.Fatal("one interface was billed twice in a circuit", result, err)
	}
	otherSource.TenantID = uuid.NewString()
	second.source = otherSource // model a foreign internal fact, never public input
	if result, err := CalculateCapacityMeasuredP95(ctx, window, "out", []CapacityMeasuredMember{first, second}); err == nil || !reflect.DeepEqual(result, CapacityMeasuredPercentile{}) {
		t.Fatal("foreign measured member entered a circuit", result, err)
	}
	points[1].UptimeKnown, points[1].UptimeTicks = false, 0
	first, err = MeasureCapacityCounterMember(ctx, source, window, points)
	if err != nil {
		t.Fatal(err)
	}
	measured, err = CalculateCapacityMeasuredP95(ctx, window, "in", []CapacityMeasuredMember{first})
	if err != nil || measured.Result().Complete || measured.Result().BPSNumerator != "" || measured.Result().MissingSamples != 2 {
		t.Fatal("missing original clocks became a shortened percentile", measured.Result(), err)
	}
	terms.Direction = "in"
	bill, err = CheckCapacityMeasuredBill(ctx, terms, measured, "", window.MemoryBytes, window.WorkUnits)
	if err != nil || bill.Complete || bill.Reason != "billing_period_incomplete" || bill.ChargeNumerator != "" {
		t.Fatal("incomplete source coverage became a bill amount", bill, err)
	}
}
