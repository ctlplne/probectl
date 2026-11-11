// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type CapacityPercentileResult struct {
	From            time.Time `json:"from"`
	To              time.Time `json:"to"`
	Model           string    `json:"model"`
	Direction       string    `json:"direction"`
	ExpectedSamples int       `json:"expected_samples"`
	ObservedSamples int       `json:"observed_samples"`
	MissingSamples  int       `json:"missing_samples"`
	Rank            int       `json:"rank,omitempty"`
	Complete        bool      `json:"complete"`
	BPSNumerator    string    `json:"bps_numerator,omitempty"`
	BPSDenominator  string    `json:"bps_denominator,omitempty"`
}

// An opaque calculation can be passed to bill comparison without accepting a
// JSON document asserting a measured percentile. This is still not a source,
// financial or current-actor grant; the serving adapter owns those checks.
type CapacityMeasuredPercentile struct {
	fact      capacityBillingPercentile
	direction string
}

func (m CapacityMeasuredPercentile) Result() CapacityPercentileResult {
	return CapacityPercentileResult{From: m.fact.from, To: m.fact.to, Model: CapacityCounterWindowModel(), Direction: m.direction,
		ExpectedSamples: m.fact.expected, ObservedSamples: m.fact.observed, MissingSamples: m.fact.missing, Rank: m.fact.rank,
		Complete: m.fact.complete, BPSNumerator: m.fact.numerator, BPSDenominator: m.fact.denominator}
}

// CalculateCapacityMeasuredP95 sums distinct currently authorized members on
// their common grid before ranking. An incomplete required direction produces
// coverage counts with no percentile; it cannot become a shorter bill period.
func CalculateCapacityMeasuredP95(ctx context.Context, window CapacityMeasurementWindow, direction string, members []CapacityMeasuredMember) (CapacityMeasuredPercentile, error) {
	none := CapacityMeasuredPercentile{}
	tenant, bound := tenancy.FromContext(ctx)
	if !bound {
		return none, tenancy.ErrNoTenant
	}
	budget := capacityGridAdmission{window.MemoryBytes / 4, window.WorkUnits / 4}
	if !budget.debit(int64(len(members)), 4096, 4096) {
		return none, errCapacityCounterInput
	}
	inputs := make([]capacityBillingMember, 0, len(members))
	for _, member := range members {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		source := member.source
		if source.TenantID != tenant.String() || len(member.in) != len(member.out) ||
			!budget.debit(int64(len(member.in)), 1024, 1024) {
			return none, errCapacityCounterInput
		}
		input := capacityBillingMember{tenant: source.TenantID, context: source.ContextID, router: source.DeviceID, iface: source.InterfaceID,
			source: source.AgentID + "/" + source.SourceRef, incarnation: source.SourceAssignedAt.Format(time.RFC3339Nano) + "/" + source.AgentAssignedAt.Format(time.RFC3339Nano),
			samples: make([]capacityBillingSample, len(member.in))}
		for i := range input.samples {
			input.samples[i] = capacityBillingSample{in: member.in[i], out: member.out[i]}
		}
		inputs = append(inputs, input)
	}
	fact, err := capacityBillingP95(ctx, capacityBillingWindow{from: window.From, to: window.To, mode: capacityBillingMode(direction),
		memoryBytes: window.MemoryBytes / 2, workUnits: window.WorkUnits / 2}, inputs)
	if err != nil {
		return none, err
	}
	return CapacityMeasuredPercentile{fact: fact, direction: direction}, nil
}

type CapacityBillResult struct {
	From                         time.Time `json:"from"`
	To                           time.Time `json:"to"`
	Model                        string    `json:"model"`
	Currency                     string    `json:"currency"`
	Complete                     bool      `json:"complete"`
	Reason                       string    `json:"reason,omitempty"`
	CommitNumerator              string    `json:"commit_numerator"`
	CommitDenominator            string    `json:"commit_denominator"`
	OverageNumerator             string    `json:"overage_numerator,omitempty"`
	OverageDenominator           string    `json:"overage_denominator,omitempty"`
	BillableNumerator            string    `json:"billable_numerator,omitempty"`
	BillableDenominator          string    `json:"billable_denominator,omitempty"`
	ChargeNumerator              string    `json:"charge_numerator,omitempty"`
	ChargeDenominator            string    `json:"charge_denominator,omitempty"`
	InvoiceCompared              bool      `json:"invoice_compared"`
	InvoiceDifferenceNumerator   string    `json:"invoice_difference_numerator,omitempty"`
	InvoiceDifferenceDenominator string    `json:"invoice_difference_denominator,omitempty"`
}

// CheckCapacityMeasuredBill uses separately authorized exact operator terms.
// The model is uniform unit price times max(commit, percentile), without tax,
// fees or an inferred invoice. No invoice rounding or float conversion occurs.
func CheckCapacityMeasuredBill(ctx context.Context, definition CapacityAgreementDefinition, measured CapacityMeasuredPercentile, invoice string, memoryBytes, workUnits int64) (CapacityBillResult, error) {
	none := CapacityBillResult{}
	tenant, bound := tenancy.FromContext(ctx)
	if !bound {
		return none, tenancy.ErrNoTenant
	}
	if definition.Direction != measured.direction {
		return none, errCapacityCounterInput
	}
	checked, err := capacityCheckBill(ctx, capacityBillingContract{tenant: tenant.String(), currency: definition.Currency, commitBPS: definition.CommitBPS,
		unitBPS: definition.UnitBPS, unitPrice: definition.UnitPrice, invoiced: invoice}, measured.fact, memoryBytes, workUnits)
	if err != nil {
		return none, err
	}
	return CapacityBillResult{From: checked.from, To: checked.to, Model: checked.model, Currency: checked.currency, Complete: checked.complete, Reason: checked.reason,
		CommitNumerator: checked.commitNumerator, CommitDenominator: checked.commitDenominator, OverageNumerator: checked.overageNumerator, OverageDenominator: checked.overageDenominator,
		BillableNumerator: checked.billableNumerator, BillableDenominator: checked.billableDenominator, ChargeNumerator: checked.chargeNumerator, ChargeDenominator: checked.chargeDenominator,
		InvoiceCompared: checked.invoiceCompared, InvoiceDifferenceNumerator: checked.invoiceDifferenceNumerator, InvoiceDifferenceDenominator: checked.invoiceDifferenceDenominator}, nil
}
