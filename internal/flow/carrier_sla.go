// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrCarrierSLAInput = errors.New("complete scoped carrier SLA terms and original measurements are required")

// These are operator contract terms, not probectl prices or a telemetry grant.
// A credit band is an explicit half-open range of the measured metric, not an
// invented industry schedule. Empty To means no upper boundary.
type CarrierSLACreditBand struct {
	From        string `json:"from_inclusive"`
	To          string `json:"to_exclusive,omitempty"`
	CreditRatio string `json:"credit_ratio"`
}

type CarrierSLARule struct {
	ID          string                 `json:"id"`
	Metric      string                 `json:"metric"`
	Basis       string                 `json:"basis"`
	GoodWhen    string                 `json:"good_when"`
	Threshold   string                 `json:"threshold"`
	CreditBands []CarrierSLACreditBand `json:"credit_bands"`
}

type CarrierSLATerms struct {
	Carrier        string           `json:"carrier"`
	CircuitID      string           `json:"circuit_id"`
	Site           string           `json:"site"`
	Currency       string           `json:"currency"`
	MonthlyCharge  string           `json:"monthly_charge"`
	Aggregation    string           `json:"aggregation"`
	CreditCapRatio string           `json:"credit_cap_ratio"`
	Rules          []CarrierSLARule `json:"rules"`
}

// A source reader supplies original coverage under current tenant/source
// authority. Neither this type nor Complete supplies that authority itself.
// Values are exact ratios/nanoseconds. Missing observations remain unknown.
type carrierSLAMeasurement struct {
	TenantID  string    `json:"-"`
	ID        string    `json:"id"`
	RuleID    string    `json:"rule_id"`
	Basis     string    `json:"basis"`
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	Value     string    `json:"value,omitempty"`
	Complete  bool      `json:"complete"`
	Citations []string  `json:"citations"`
}

type carrierSLAAssessment struct {
	MeasurementID string    `json:"measurement_id,omitempty"`
	RuleID        string    `json:"rule_id"`
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	State         string    `json:"state"`
	Value         string    `json:"value,omitempty"`
	CreditRatio   string    `json:"credit_ratio,omitempty"`
	Citations     []string  `json:"citations"`
}

type carrierSLACredit struct {
	From                  time.Time              `json:"from"`
	To                    time.Time              `json:"to"`
	Currency              string                 `json:"currency"`
	Complete              bool                   `json:"complete"`
	KnownCreditLowerBound string                 `json:"known_credit_lower_bound"`
	ExactCredit           *string                `json:"exact_credit,omitempty"`
	Assessments           []carrierSLAAssessment `json:"assessments"`
}

// assessCarrierSLA performs only exact contract arithmetic over a complete
// admitted input. It cannot infer downtime, cause, current authorization or a
// legally payable amount from incident text, absent polls or partial coverage.
func assessCarrierSLA(ctx context.Context, terms CarrierSLATerms, from, to time.Time, measurements []carrierSLAMeasurement, memory, work int64) (carrierSLACredit, error) {
	none := carrierSLACredit{}
	tenant, bound := tenancy.FromContext(ctx)
	if !bound {
		return none, tenancy.ErrNoTenant
	}
	if from.IsZero() || !to.After(from) || len(terms.Rules) == 0 || memory < 4096 || work < 4096 {
		return none, ErrCarrierSLAInput
	}
	_, _, err := carrierSLACost(ctx, terms, measurements, memory, work)
	if err != nil {
		return none, err
	}
	charge, err := capacityContractDecimal(ctx, terms.MonthlyCharge)
	if err != nil {
		return none, ErrCarrierSLAInput
	}
	capRatio, err := capacityContractDecimal(ctx, terms.CreditCapRatio)
	if err != nil {
		return none, ErrCarrierSLAInput
	}
	if !capacityAgreementText(terms.Carrier, true) || !capacityAgreementText(terms.CircuitID, true) || !capacityAgreementText(terms.Currency, true) || !capacityAgreementText(terms.Site, false) || terms.Aggregation != "maximum" && terms.Aggregation != "sum_capped" {
		return none, ErrCarrierSLAInput
	}
	rules := map[string]CarrierSLARule{}
	for _, rule := range terms.Rules {
		if _, exists := rules[rule.ID]; exists {
			return none, ErrCarrierSLAInput
		}
		if err := validateCarrierSLARule(ctx, rule); err != nil {
			return none, err
		}
		rules[rule.ID] = rule
	}
	result := carrierSLACredit{From: from, To: to, Currency: terms.Currency, Complete: true, Assessments: []carrierSLAAssessment{}}
	seen, observed := map[string]bool{}, map[string]bool{}
	total := new(big.Rat)
	for _, measurement := range measurements {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		rule, exists := rules[measurement.RuleID]
		if measurement.TenantID != tenant.String() {
			return none, tenancy.ErrNoTenant
		}
		if !exists || !capacityAgreementText(measurement.ID, true) || seen[measurement.ID] || measurement.Basis != rule.Basis || measurement.From.Before(from) || measurement.To.After(to) || !measurement.To.After(measurement.From) {
			return none, ErrCarrierSLAInput
		}
		seen[measurement.ID], observed[rule.ID] = true, true
		assessment := carrierSLAAssessment{MeasurementID: measurement.ID, RuleID: rule.ID, From: measurement.From, To: measurement.To, State: "unknown", Citations: append([]string{}, measurement.Citations...)}
		if !measurement.Complete {
			result.Complete = false
			result.Assessments = append(result.Assessments, assessment)
			continue
		}
		if len(measurement.Citations) == 0 {
			return none, ErrCarrierSLAInput
		}
		value, err := carrierSLARational(ctx, measurement.Value)
		if err != nil {
			return none, err
		}
		if (rule.Metric == "availability" || rule.Metric == "loss") && value.Cmp(big.NewRat(1, 1)) > 0 {
			return none, ErrCarrierSLAInput
		}
		threshold, err := carrierSLARational(ctx, rule.Threshold)
		if err != nil {
			return none, err
		}
		assessment.Value, assessment.State = value.RatString(), "met"
		breached := carrierSLABreached(rule.GoodWhen, value.Cmp(threshold))
		if breached {
			assessment.State = "breached"
			ratio, err := carrierSLACreditRatio(ctx, rule, value)
			if err != nil {
				return none, err
			}
			assessment.CreditRatio = ratio.RatString()
			if terms.Aggregation == "maximum" {
				if ratio.Cmp(total) > 0 {
					total.Set(ratio)
				}
			} else {
				total.Add(total, ratio)
			}
		}
		result.Assessments = append(result.Assessments, assessment)
	}
	for _, rule := range terms.Rules {
		if !observed[rule.ID] {
			result.Complete = false
			result.Assessments = append(result.Assessments, carrierSLAAssessment{RuleID: rule.ID, From: from, To: to, State: "unknown", Citations: []string{}})
		}
	}
	if total.Cmp(capRatio) > 0 {
		total.Set(capRatio)
	}
	amount := new(big.Rat).Mul(total, charge).RatString()
	result.KnownCreditLowerBound = amount
	if result.Complete {
		result.ExactCredit = &amount
	}
	return result, ctx.Err()
}

func carrierSLARational(ctx context.Context, text string) (*big.Rat, error) {
	numerator, denominator, fraction := strings.Cut(text, "/")
	if !fraction {
		value, err := capacityContractDecimal(ctx, text)
		if err != nil {
			return nil, ErrCarrierSLAInput
		}
		return value, nil
	}
	top, err := capacityUnsignedInteger(ctx, numerator)
	if err != nil {
		return nil, ErrCarrierSLAInput
	}
	bottom, err := capacityUnsignedInteger(ctx, denominator)
	if err != nil || bottom.Sign() == 0 {
		return nil, ErrCarrierSLAInput
	}
	return new(big.Rat).SetFrac(top, bottom), nil
}

func validateCarrierSLARule(ctx context.Context, rule CarrierSLARule) error {
	if !capacityAgreementText(rule.ID, true) || !capacityAgreementText(rule.Basis, true) || rule.GoodWhen != "at_least" && rule.GoodWhen != "at_most" && rule.GoodWhen != "greater_than" && rule.GoodWhen != "less_than" || len(rule.CreditBands) == 0 {
		return ErrCarrierSLAInput
	}
	switch rule.Metric {
	case "availability", "loss", "latency_nanos", "repair_nanos":
	default:
		return ErrCarrierSLAInput
	}
	threshold, err := carrierSLARational(ctx, rule.Threshold)
	if err != nil {
		return err
	}
	if (rule.Metric == "availability" || rule.Metric == "loss") && threshold.Cmp(big.NewRat(1, 1)) > 0 {
		return ErrCarrierSLAInput
	}
	type interval struct{ lower, upper *big.Rat }
	intervals := make([]interval, 0, len(rule.CreditBands))
	for _, band := range rule.CreditBands {
		lower, err := carrierSLARational(ctx, band.From)
		if err != nil {
			return err
		}
		var upper *big.Rat
		if band.To != "" {
			upper, err = carrierSLARational(ctx, band.To)
			if err != nil || upper.Cmp(lower) <= 0 {
				return ErrCarrierSLAInput
			}
		}
		if _, err := capacityContractDecimal(ctx, band.CreditRatio); err != nil {
			return ErrCarrierSLAInput
		}
		intervals = append(intervals, interval{lower, upper})
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].lower.Cmp(intervals[j].lower) < 0 })
	for i := 1; i < len(intervals); i++ {
		previous := intervals[i-1]
		if previous.upper == nil || intervals[i].lower.Cmp(previous.upper) < 0 {
			return ErrCarrierSLAInput
		}
	}

	return ctx.Err()
}

func carrierSLACreditRatio(ctx context.Context, rule CarrierSLARule, value *big.Rat) (*big.Rat, error) {
	var selected *big.Rat
	for _, band := range rule.CreditBands {
		lower, err := carrierSLARational(ctx, band.From)
		if err != nil {
			return nil, err
		}
		if value.Cmp(lower) < 0 {
			continue
		}
		if band.To != "" {
			upper, err := carrierSLARational(ctx, band.To)
			if err != nil {
				return nil, err
			}
			if value.Cmp(upper) >= 0 {
				continue
			}
		}
		if selected != nil {
			return nil, ErrCarrierSLAInput
		}
		selected, err = capacityContractDecimal(ctx, band.CreditRatio)
		if err != nil {
			return nil, ErrCarrierSLAInput
		}
	}
	if selected == nil {
		return nil, ErrCarrierSLAInput
	}
	return selected, nil
}

func carrierSLACost(ctx context.Context, terms CarrierSLATerms, measurements []carrierSLAMeasurement, memory, work int64) (int64, int64, error) {
	remaining := memory
	initialWork := work
	charge := func(text string) error {
		size := int64(len(text))
		words := size/8 + 1
		if size > remaining/64 || words > work/512 || words > (work/512)/words {
			return ErrCapacityAgreementBudget
		}
		remaining -= size * 64
		work -= words * words * 512
		return ctx.Err()
	}
	if int64(len(terms.Rules))+int64(len(measurements)) > remaining/4096 {
		return 0, 0, ErrCapacityAgreementBudget
	}
	remaining -= 4096 * (int64(len(terms.Rules)) + int64(len(measurements)))
	for _, text := range []string{terms.Carrier, terms.CircuitID, terms.Site, terms.Currency, terms.MonthlyCharge, terms.CreditCapRatio, terms.Aggregation} {
		if err := charge(text); err != nil {
			return 0, 0, err
		}
	}
	for _, rule := range terms.Rules {
		for _, text := range []string{rule.ID, rule.Metric, rule.Basis, rule.GoodWhen, rule.Threshold} {
			if err := charge(text); err != nil {
				return 0, 0, err
			}
		}
		if int64(len(rule.CreditBands)) > remaining/2048 {
			return 0, 0, ErrCapacityAgreementBudget
		}
		remaining -= int64(len(rule.CreditBands)) * 2048
		for _, band := range rule.CreditBands {
			for _, text := range []string{band.From, band.To, band.CreditRatio} {
				if err := charge(text); err != nil {
					return 0, 0, err
				}
			}
		}
	}
	for _, measurement := range measurements {
		if int64(len(measurement.Citations)) > remaining/128 {
			return 0, 0, ErrCapacityAgreementBudget
		}
		remaining -= int64(len(measurement.Citations)) * 128
		for _, text := range []string{measurement.TenantID, measurement.ID, measurement.RuleID, measurement.Basis, measurement.Value} {
			if err := charge(text); err != nil {
				return 0, 0, err
			}
		}
		for _, citation := range measurement.Citations {
			if !capacityAgreementText(citation, true) {
				return 0, 0, ErrCarrierSLAInput
			}
			if err := charge(citation); err != nil {
				return 0, 0, err
			}
		}
	}
	return memory - remaining, initialWork - work, ctx.Err()
}

// Existing agreement revisions retain these optional terms. This normalizer
// introduces no source selectors and preserves the parent's tenant/FK boundary.
func normalizeCarrierSLATerms(ctx context.Context, input CarrierSLATerms, memory, work int64) (CarrierSLATerms, int64, int64, error) {
	none := CarrierSLATerms{}
	usedMemory, usedWork, err := carrierSLACost(ctx, input, nil, memory, work)
	if err != nil {
		return none, 0, 0, err
	}
	if !capacityAgreementText(input.Carrier, true) || !capacityAgreementText(input.CircuitID, true) || !capacityAgreementText(input.Currency, true) || !capacityAgreementText(input.Site, false) || input.Aggregation != "maximum" && input.Aggregation != "sum_capped" || len(input.Rules) == 0 {
		return none, 0, 0, ErrCarrierSLAInput
	}
	if _, err := capacityContractDecimal(ctx, input.MonthlyCharge); err != nil {
		return none, 0, 0, ErrCarrierSLAInput
	}
	_, err = capacityContractDecimal(ctx, input.CreditCapRatio)
	if err != nil {
		return none, 0, 0, ErrCarrierSLAInput
	}
	seen := map[string]bool{}
	output := input
	output.Rules = append([]CarrierSLARule(nil), input.Rules...)
	for index, rule := range output.Rules {
		if seen[rule.ID] {
			return none, 0, 0, ErrCarrierSLAInput
		}
		seen[rule.ID] = true
		if err := validateCarrierSLARule(ctx, rule); err != nil {
			return none, 0, 0, err
		}
		output.Rules[index].CreditBands = append([]CarrierSLACreditBand(nil), rule.CreditBands...)
	}
	return output, usedMemory, usedWork, ctx.Err()
}

func carrierSLABreached(goodWhen string, comparison int) bool {
	switch goodWhen {
	case "at_least":
		return comparison < 0
	case "at_most":
		return comparison > 0
	case "greater_than":
		return comparison <= 0
	case "less_than":
		return comparison >= 0
	default:
		return true // only normalized operators can reach the calculator
	}
}
