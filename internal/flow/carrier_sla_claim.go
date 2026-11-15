// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"math/big"
	"sort"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type CarrierSLASelection struct {
	AgreementID string `json:"agreement_id"`
	Version     string `json:"version"`
	At          string `json:"at"`
}

type CarrierSLAClaimRequest struct {
	Selections []CarrierSLASelection `json:"selections"`
}

type CarrierSLAClaimGroup struct {
	Carrier               string                `json:"carrier"`
	Currency              string                `json:"currency"`
	Period                CapacityBillingPeriod `json:"period"`
	Complete              bool                  `json:"complete"`
	KnownCreditLowerBound string                `json:"known_credit_lower_bound"`
	ExactCredit           *string               `json:"exact_credit,omitempty"`
	Circuits              []CarrierSLAStatement `json:"circuits"`
}

type CarrierSLAClaimDraft struct {
	ContractVersion  string                 `json:"contract_version"`
	Groups           []CarrierSLAClaimGroup `json:"groups"`
	GeneratedAt      time.Time              `json:"generated_at"`
	SourceValidUntil time.Time              `json:"source_valid_until"`
	HumanReview      bool                   `json:"human_review_required"`
	SubmissionState  string                 `json:"submission_state"`
}

type carrierSLAGroupKey struct {
	carrier, currency, timezone string
	from, to                    time.Time
	day                         int
}

// GroupCarrierSLAClaims groups already-authorized complete circuit statements,
// preserving distinct currencies and billing calendars. This is exact draft
// arithmetic, never source authority, adjudication or automatic submission.
func GroupCarrierSLAClaims(ctx context.Context, statements []CarrierSLAStatement, memory, work int64) (CarrierSLAClaimDraft, error) {
	none := CarrierSLAClaimDraft{}
	tenant, bound := tenancy.FromContext(ctx)
	if !bound {
		return none, tenancy.ErrNoTenant
	}
	if len(statements) == 0 {
		return none, ErrCarrierSLAInput
	}
	if memory < 8192 || int64(len(statements)) > memory/4096 || work < 4096 {
		return none, ErrCapacityAgreementBudget
	}
	groups := map[carrierSLAGroupKey]*CarrierSLAClaimGroup{}
	seen := map[struct {
		id, version string
		from, to    time.Time
	}]bool{}
	result := CarrierSLAClaimDraft{ContractVersion: "probectl-carrier-sla-draft/v1", Groups: []CarrierSLAClaimGroup{}, GeneratedAt: time.Now().UTC(), HumanReview: true, SubmissionState: "not_submitted"}
	for _, statement := range statements {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if statement.Agreement.TenantID != tenant.String() {
			return none, tenancy.ErrNoTenant
		}
		terms := statement.Agreement.Definition.SLA
		if terms == nil || statement.Credit.Currency != terms.Currency || statement.Period.From.IsZero() || !statement.Period.To.After(statement.Period.From) || !statement.Credit.From.Equal(statement.Period.From) || !statement.Credit.To.Equal(statement.Period.To) || !statement.HumanReview {
			return none, ErrCarrierSLAInput
		}
		identity := struct {
			id, version string
			from, to    time.Time
		}{statement.Agreement.ID, statement.Agreement.Version, statement.Period.From.UTC(), statement.Period.To.UTC()}
		if identity.id == "" || identity.version == "" || seen[identity] {
			return none, ErrCarrierSLAInput
		}
		seen[identity] = true
		key := carrierSLAGroupKey{terms.Carrier, terms.Currency, statement.Period.Timezone, statement.Period.From.UTC(), statement.Period.To.UTC(), statement.Period.BillingDay}
		group := groups[key]
		if group == nil {
			group = &CarrierSLAClaimGroup{Carrier: terms.Carrier, Currency: terms.Currency, Period: statement.Period, Complete: true, KnownCreditLowerBound: "0", Circuits: []CarrierSLAStatement{}}
			groups[key] = group
		}
		for _, value := range []string{statement.Credit.KnownCreditLowerBound, group.KnownCreditLowerBound} {
			cost := int64(len(value)) + 1
			words := cost/8 + 1
			if cost > memory/64 || words > work/512 || words > (work/512)/words {
				return none, ErrCapacityAgreementBudget
			}
			memory -= cost * 64
			work -= words * words * 512
		}
		amount, err := carrierSLARational(ctx, statement.Credit.KnownCreditLowerBound)
		if err != nil {
			return none, err
		}
		total, err := carrierSLARational(ctx, group.KnownCreditLowerBound)
		if err != nil {
			return none, err
		}
		group.KnownCreditLowerBound = new(big.Rat).Add(total, amount).RatString()
		if statement.Credit.Complete != (statement.Credit.ExactCredit != nil) {
			return none, ErrCarrierSLAInput
		}
		if statement.Credit.ExactCredit != nil && *statement.Credit.ExactCredit != statement.Credit.KnownCreditLowerBound {
			return none, ErrCarrierSLAInput
		}
		group.Complete = group.Complete && statement.Credit.Complete
		group.Circuits = append(group.Circuits, statement)
		if result.SourceValidUntil.IsZero() || statement.SourceValidUntil.Before(result.SourceValidUntil) {
			result.SourceValidUntil = statement.SourceValidUntil
		}
	}
	for _, group := range groups {
		if group.Complete {
			value := group.KnownCreditLowerBound
			group.ExactCredit = &value
		}
		sort.Slice(group.Circuits, func(i, j int) bool {
			a, b := group.Circuits[i].Agreement, group.Circuits[j].Agreement
			return a.ID < b.ID || a.ID == b.ID && a.Version < b.Version
		})
		result.Groups = append(result.Groups, *group)
	}
	sort.Slice(result.Groups, func(i, j int) bool {
		return carrierSLAClaimGroupLess(result.Groups[i], result.Groups[j])
	})
	return result, ctx.Err()
}

func carrierSLAClaimGroupLess(a, b CarrierSLAClaimGroup) bool {
	if a.Carrier != b.Carrier {
		return a.Carrier < b.Carrier
	}
	if a.Currency != b.Currency {
		return a.Currency < b.Currency
	}
	if !a.Period.From.Equal(b.Period.From) {
		return a.Period.From.Before(b.Period.From)
	}
	if !a.Period.To.Equal(b.Period.To) {
		return a.Period.To.Before(b.Period.To)
	}
	if a.Period.Timezone != b.Period.Timezone {
		return a.Period.Timezone < b.Period.Timezone
	}
	return a.Period.BillingDay < b.Period.BillingDay
}
