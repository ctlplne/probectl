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

func carrierSLAGroupFixture(tenant, id, currency, credit string) CarrierSLAStatement {
	from := time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 1, 0)
	return CarrierSLAStatement{Agreement: CapacityAgreement{TenantID: tenant, ID: id, Version: "1", Definition: CapacityAgreementDefinition{SLA: &CarrierSLATerms{Carrier: "operator carrier", CircuitID: id, Currency: currency}}}, Period: CapacityBillingPeriod{From: from, To: to, Timezone: "UTC", BillingDay: 1}, Credit: CarrierSLACredit{From: from, To: to, Currency: currency, Complete: true, KnownCreditLowerBound: credit, ExactCredit: &credit, Assessments: []CarrierSLAAssessment{}}, SourceValidUntil: time.Now().UTC().Add(time.Hour), HumanReview: true}
}

func TestCarrierSLAClaimGroupsKeepAllCircuitsCalendarsAndExactCurrencies(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	a := carrierSLAGroupFixture(tenant, "a", "USD", "1/3")
	b := carrierSLAGroupFixture(tenant, "b", "USD", "1/7")
	c := carrierSLAGroupFixture(tenant, "c", "EUR", "100000000000000000001/1000000000000000000")
	d := carrierSLAGroupFixture(tenant, "d", "USD", "1/11")
	d.Period.Timezone = "Etc/UTC"
	result, err := GroupCarrierSLAClaims(ctx, []CarrierSLAStatement{b, d, c, a}, 8<<20, 8<<20)
	if err != nil || len(result.Groups) != 3 || !result.HumanReview || result.SubmissionState != "not_submitted" {
		t.Fatal("complete grouping lost currencies or billing calendars", result, err)
	}
	var usd *CarrierSLAClaimGroup
	for i := range result.Groups {
		group := &result.Groups[i]
		if group.Currency == "USD" && group.Period.Timezone == "UTC" {
			usd = group
		}
	}
	if usd == nil || !usd.Complete || usd.ExactCredit == nil || *usd.ExactCredit != "10/21" || len(usd.Circuits) != 2 || usd.Circuits[0].Agreement.ID != "a" || usd.Circuits[1].Agreement.ID != "b" {
		t.Fatal("group totals rounded or dropped selected circuits", usd)
	}
	b.Credit.Complete = false
	b.Credit.ExactCredit = nil
	result, err = GroupCarrierSLAClaims(ctx, []CarrierSLAStatement{a, b}, 8<<20, 8<<20)
	if err != nil || result.Groups[0].Complete || result.Groups[0].ExactCredit != nil || result.Groups[0].KnownCreditLowerBound != "10/21" {
		t.Fatal("unknown circuit acquired an exact group total or lost known lower bound", result, err)
	}
	if _, err := GroupCarrierSLAClaims(ctx, []CarrierSLAStatement{a, a}, 8<<20, 8<<20); err == nil {
		t.Fatal("same agreement revision and calendar period counted twice")
	}
}

func TestCarrierSLAClaimGroupsRefuseForeignTenantAndInvalidCredit(t *testing.T) {
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		owned := carrierSLAGroupFixture(tenant, "owned", "USD", "1/3")
		foreign := carrierSLAGroupFixture("foreign", "foreign", "USD", "1/7")
		result, err := GroupCarrierSLAClaims(ctx, []CarrierSLAStatement{owned, foreign}, 8<<20, 8<<20)
		if !errors.Is(err, tenancy.ErrNoTenant) || len(result.Groups) != 0 {
			t.Fatal("foreign circuit crossed tenant or returned a partial group", err)
		}
		for _, change := range []func(*CarrierSLAStatement){
			func(s *CarrierSLAStatement) { s.Credit.Currency = "EUR" },
			func(s *CarrierSLAStatement) { s.Credit.KnownCreditLowerBound = "-1" },
			func(s *CarrierSLAStatement) { s.Credit.Complete = false },
			func(s *CarrierSLAStatement) { s.HumanReview = false },
		} {
			invalid := owned
			change(&invalid)
			if _, err := GroupCarrierSLAClaims(ctx, []CarrierSLAStatement{invalid}, 8<<20, 8<<20); err == nil {
				t.Fatal("invalid financial claim acquired a group total")
			}
		}
		if result, err := GroupCarrierSLAClaims(ctx, []CarrierSLAStatement{owned}, 8<<20, 8<<20); err != nil || len(result.Groups) != 1 {
			t.Fatal("valid tenant control failed", err)
		}
	}
}
