// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestCarrierSLAUsesExactContractBandsCapsAndUnknownCoverage(t *testing.T) {
	from := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 1, 0)
	for _, tenant := range []string{"primary", "paired"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		terms := CarrierSLATerms{Carrier: "Operator carrier", CircuitID: "WAN circuit", Currency: "USD", MonthlyCharge: "100.000000000000000001", Aggregation: "sum_capped", CreditCapRatio: "0.25", Rules: []CarrierSLARule{
			{ID: "availability", Metric: "availability", Basis: "complete_original_execution_ratio", GoodWhen: "at_least", Threshold: "0.999", CreditBands: []CarrierSLACreditBand{{From: "0", To: "0.99", CreditRatio: "0.5"}, {From: "0.99", To: "0.999", CreditRatio: "0.1"}}},
			{ID: "loss", Metric: "loss", Basis: "complete_original_packet_ratio", GoodWhen: "at_most", Threshold: "0.01", CreditBands: []CarrierSLACreditBand{{From: "0.01", CreditRatio: "0.2"}}},
		}}
		measured := []carrierSLAMeasurement{{TenantID: tenant, ID: "availability-month", RuleID: "availability", Basis: terms.Rules[0].Basis, From: from, To: to, Value: "0.995", Complete: true, Citations: []string{"original-probe-a", "original-probe-b"}}, {TenantID: tenant, ID: "loss-month", RuleID: "loss", Basis: terms.Rules[1].Basis, From: from, To: to, Value: "1/50", Complete: true, Citations: []string{"original-packets"}}}
		result, err := assessCarrierSLA(ctx, terms, from, to, measured, 8<<20, 8<<20)
		if err != nil || !result.Complete || result.ExactCredit == nil || *result.ExactCredit != "100000000000000000001/4000000000000000000" || len(result.Assessments) != 2 || result.Assessments[0].CreditRatio != "1/10" || result.Assessments[1].CreditRatio != "1/5" {
			t.Fatal("exact contract schedule/cap changed", result, err)
		}
		terms.Aggregation = "maximum"
		result, err = assessCarrierSLA(ctx, terms, from, to, measured, 8<<20, 8<<20)
		if err != nil || result.ExactCredit == nil || *result.ExactCredit != "100000000000000000001/5000000000000000000" {
			t.Fatal("maximum clause aggregation became a sum", result, err)
		}
		measured[1].Complete = false
		result, err = assessCarrierSLA(ctx, terms, from, to, measured, 8<<20, 8<<20)
		if err != nil || result.Complete || result.ExactCredit != nil || result.KnownCreditLowerBound != "100000000000000000001/10000000000000000000" || result.Assessments[1].State != "unknown" {
			t.Fatal("missing coverage became a complete claim or invented zero", result, err)
		}
		result, err = assessCarrierSLA(ctx, terms, from, to, nil, 8<<20, 8<<20)
		if err != nil || result.Complete || result.ExactCredit != nil || len(result.Assessments) != 2 || result.Assessments[0].State != "unknown" {
			t.Fatal("absent measurements became met clauses", result, err)
		}
		measured[1].Complete = true
		measured[0].Value = "0.999"
		measured[1].Value = "0.01"
		result, err = assessCarrierSLA(ctx, terms, from, to, measured, 8<<20, 8<<20)
		if err != nil || result.ExactCredit == nil || *result.ExactCredit != "0" || result.Assessments[0].State != "met" || result.Assessments[1].State != "met" {
			t.Fatal("inclusive exact goal boundaries gained a breach", result, err)
		}
		// Operator penalties may exceed one monthly charge. No product-imposed
		//100-percent ceiling replaces the actual contract's explicit cap.
		terms.CreditCapRatio = "3"
		terms.Rules[0].CreditBands[0].CreditRatio = "2"
		measured[0].Value = "0.98"
		result, err = assessCarrierSLA(ctx, terms, from, to, measured, 8<<20, 8<<20)
		if err != nil || result.ExactCredit == nil || *result.ExactCredit != "100000000000000000001/500000000000000000" {
			t.Fatal("operator credit terms were limited to an arbitrary monthly charge", result, err)
		}
	}
}

func TestCarrierSLAFailsClosedAcrossTenantsAndIncompleteContractBasis(t *testing.T) {
	from, to := time.Now().Add(-time.Hour), time.Now()
	terms := CarrierSLATerms{Carrier: "Carrier", CircuitID: "Circuit", Currency: "USD", MonthlyCharge: "100", Aggregation: "maximum", CreditCapRatio: "1", Rules: []CarrierSLARule{{ID: "loss", Metric: "loss", Basis: "original_packet_ratio", GoodWhen: "at_most", Threshold: "0.01", CreditBands: []CarrierSLACreditBand{{From: "0.01", CreditRatio: "0.2"}}}}}
	for _, tenant := range []string{"primary", "paired"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		measurement := carrierSLAMeasurement{TenantID: tenant, ID: "original", RuleID: "loss", Basis: terms.Rules[0].Basis, From: from, To: to, Value: "1/10", Complete: true, Citations: []string{"original-receipt"}}
		foreign := measurement
		foreign.TenantID = "foreign"
		if result, err := assessCarrierSLA(ctx, terms, from, to, []carrierSLAMeasurement{foreign}, 8<<20, 8<<20); !errors.Is(err, tenancy.ErrNoTenant) || result.Currency != "" {
			t.Fatal("foreign measurements entered a contractual claim", result, err)
		}
		for _, change := range []func(*carrierSLAMeasurement){func(v *carrierSLAMeasurement) { v.Citations = nil }, func(v *carrierSLAMeasurement) { v.Value = "NaN" }, func(v *carrierSLAMeasurement) { v.Basis = "inferred_from_incident_title" }, func(v *carrierSLAMeasurement) { v.From = from.Add(-time.Nanosecond) }, func(v *carrierSLAMeasurement) { v.Value = "1/0" }} {
			invalid := measurement
			change(&invalid)
			if result, err := assessCarrierSLA(ctx, terms, from, to, []carrierSLAMeasurement{invalid}, 8<<20, 8<<20); err == nil || result.Currency != "" {
				t.Fatal("incomplete original/contract basis produced a claim", result, err)
			}
		}
		if result, err := assessCarrierSLA(ctx, terms, from, to, []carrierSLAMeasurement{measurement}, 4096, 4096); err == nil || result.Currency != "" {
			t.Fatal("under-admitted claim returned a partial result", result, err)
		}
	}
}

func TestCapacityAgreementRetainsCarrierSLATermsWithoutChangingLegacyDefinitions(t *testing.T) {
	for _, tenant := range []string{"primary", "paired"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		input := capacityAgreementFixture()
		if got, err := NormalizeCapacityAgreement(ctx, input, 8<<20, 8<<20); err != nil || got.SLA != nil {
			t.Fatal("legacy agreement changed when no SLA was supplied", err)
		}
		input.SLA = &CarrierSLATerms{Carrier: "operator carrier", CircuitID: "operator circuit", Currency: "USD", MonthlyCharge: "100.000000000000000001", CreditCapRatio: "0", Aggregation: "maximum", Rules: []CarrierSLARule{{ID: "loss", Metric: "loss", Basis: "original_packet_ratio", GoodWhen: "less_than", Threshold: "0.01", CreditBands: []CarrierSLACreditBand{{From: "0.01", CreditRatio: "0"}}}}}
		got, err := NormalizeCapacityAgreement(ctx, input, 8<<20, 8<<20)
		if err != nil || got.SLA == nil || got.SLA.MonthlyCharge != input.SLA.MonthlyCharge || got.SLA.CreditCapRatio != "0" {
			t.Fatal("exact SLA metadata or a zero-credit contract was refused", err)
		}
		input.SLA.Rules[0].CreditBands[0].CreditRatio = "0.5"
		if got.SLA.Rules[0].CreditBands[0].CreditRatio != "0" {
			t.Fatal("normalized SLA retained mutable caller bands")
		}
		input.SLA.Rules[0].CreditBands = append(input.SLA.Rules[0].CreditBands, CarrierSLACreditBand{From: "0.02", CreditRatio: "0.1"})
		if _, err := NormalizeCapacityAgreement(ctx, input, 8<<20, 8<<20); !errors.Is(err, ErrCapacityAgreementInvalid) {
			t.Fatal("overlapping contract bands were saved as usable terms", err)
		}
	}
}

func TestCarrierSLARecordedSourcesAreCanonicalUniqueAndCopied(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), "primary")
	input := capacityAgreementFixture()
	input.SLA = &CarrierSLATerms{Carrier: "carrier", CircuitID: "circuit", Currency: "USD", MonthlyCharge: "100", CreditCapRatio: "1", Aggregation: "maximum", Sources: []CarrierSLASource{{AgentID: "original-agent", TestID: "44444444-4444-4444-8444-444444444444"}}, Rules: []CarrierSLARule{{ID: "loss", Metric: "loss", Basis: "original_packet_ratio", GoodWhen: "at_most", Threshold: "0.01", CreditBands: []CarrierSLACreditBand{{From: "0.01", CreditRatio: "0.1"}}}}}
	got, err := NormalizeCapacityAgreement(ctx, input, 8<<20, 8<<20)
	if err != nil || got.SLA == nil || len(got.SLA.Sources) != 1 || got.SLA.Sources[0] != input.SLA.Sources[0] {
		t.Fatal("explicit circuit source selector changed", err)
	}
	input.SLA.Sources[0].AgentID = "changed-agent"
	if got.SLA.Sources[0].AgentID != "original-agent" {
		t.Fatal("recorded source retained mutable caller input")
	}
	input.SLA.Sources = append(input.SLA.Sources, input.SLA.Sources[0])
	if _, err := NormalizeCapacityAgreement(ctx, input, 8<<20, 8<<20); !errors.Is(err, ErrCapacityAgreementInvalid) {
		t.Fatal("duplicate source selection was accepted", err)
	}
	input.SLA.Sources = []CarrierSLASource{{AgentID: "original-agent", TestID: "not-a-canonical-test"}}
	if _, err := NormalizeCapacityAgreement(ctx, input, 8<<20, 8<<20); !errors.Is(err, ErrCapacityAgreementInvalid) {
		t.Fatal("unbound test selector was accepted", err)
	}
}
