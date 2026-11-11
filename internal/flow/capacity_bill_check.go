// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"math/big"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// These are already-authorized operator agreement facts, not prices inferred
// from telemetry. The explicit model charges a uniform recorded unit rate on
// max(commit, measured percentile); tax, discounts and other fees are excluded.
type capacityBillingContract struct {
	tenant, currency              string
	commitBPS, unitBPS, unitPrice string
	invoiced                      string // Optional recorded invoice total in this same currency.
}

type capacityBillCheck struct {
	from, to                                                 time.Time
	tenant, currency, model                                  string
	complete                                                 bool
	reason                                                   string
	commitNumerator, commitDenominator                       string
	overageNumerator, overageDenominator                     string
	billableNumerator, billableDenominator                   string
	chargeNumerator, chargeDenominator                       string
	invoiceCompared                                          bool
	invoiceDifferenceNumerator, invoiceDifferenceDenominator string
}

func capacityCheckBill(ctx context.Context, contract capacityBillingContract, measured capacityBillingPercentile, memoryBytes, workUnits int64) (capacityBillCheck, error) {
	none := capacityBillCheck{}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return none, tenancy.ErrNoTenant
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if contract.tenant == "" || contract.tenant != tenant.String() || measured.tenant != tenant.String() || measured.from.IsZero() || !measured.to.After(measured.from) || contract.currency == "" || strings.TrimSpace(contract.currency) != contract.currency || !utf8.ValidString(contract.currency) || strings.IndexFunc(contract.currency, unicode.IsControl) >= 0 || memoryBytes < 4096 || workUnits < 4096 {
		return none, errCapacityCounterInput
	}
	span := measured.to.Sub(measured.from)
	if span <= 0 || !measured.from.Add(span).Equal(measured.to) || int64(measured.expected) != int64(1+(span-1)/(5*time.Minute)) {
		return none, errCapacityCounterInput
	}
	// Bound parsing, multiplication and comparison by the actual word sizes,
	// not an arbitrary currency precision or maximum supported line rate.
	memoryBytes, workUnits = memoryBytes-4096, workUnits-4096
	words := int64(1)
	for _, value := range []string{contract.tenant, contract.currency, contract.commitBPS, contract.unitBPS, contract.unitPrice, contract.invoiced, measured.numerator, measured.denominator} {
		size := int64(len(value))
		if size > memoryBytes/64 || size > workUnits/64 {
			return none, errCapacityCounterInput
		}
		memoryBytes, workUnits = memoryBytes-size*64, workUnits-size*64
		words += size/8 + 1
	}
	if words > workUnits/512 || words > (workUnits/512)/words {
		return none, errCapacityCounterInput
	}
	commit, err := capacityContractDecimal(ctx, contract.commitBPS)
	if err != nil {
		return none, err
	}
	unit, err := capacityContractDecimal(ctx, contract.unitBPS)
	if err != nil || unit.Sign() == 0 {
		return none, errCapacityCounterInput
	}
	price, err := capacityMonetaryDecimal(ctx, contract.unitPrice)
	if err != nil {
		return none, err
	}
	var invoice *big.Rat
	if contract.invoiced != "" {
		invoice, err = capacityMonetaryDecimal(ctx, contract.invoiced)
		if err != nil {
			return none, err
		}
	}
	result := capacityBillCheck{tenant: contract.tenant, from: measured.from, to: measured.to, currency: contract.currency, model: "uniform_unit_rate_with_commit_floor", commitNumerator: commit.Num().String(), commitDenominator: commit.Denom().String()}
	if !measured.complete {
		if measured.expected <= 0 || measured.observed < 0 || measured.missing <= 0 || measured.observed > measured.expected || measured.missing != measured.expected-measured.observed || measured.numerator != "" || measured.denominator != "" {
			return none, errCapacityCounterInput
		}
		result.reason = "billing_period_incomplete"
		return result, nil
	}
	if measured.expected <= 0 || measured.observed != measured.expected || measured.missing != 0 || measured.rank != measured.expected-measured.expected/20 {
		return none, errCapacityCounterInput
	}
	numerator, err := capacityUnsignedInteger(ctx, measured.numerator)
	if err != nil {
		return none, err
	}
	denominator, err := capacityUnsignedInteger(ctx, measured.denominator)
	if err != nil || denominator.Sign() == 0 {
		return none, errCapacityCounterInput
	}
	rate := new(big.Rat).SetFrac(numerator, denominator)
	overage := new(big.Rat).Sub(rate, commit)
	if overage.Sign() < 0 {
		overage.SetInt64(0)
	}
	billable := new(big.Rat).Add(commit, overage)
	charge := new(big.Rat).Mul(new(big.Rat).Quo(billable, unit), price)
	if err := ctx.Err(); err != nil {
		return none, err
	}
	result.overageNumerator, result.overageDenominator = overage.Num().String(), overage.Denom().String()
	result.billableNumerator, result.billableDenominator = billable.Num().String(), billable.Denom().String()
	result.chargeNumerator, result.chargeDenominator = charge.Num().String(), charge.Denom().String()
	if invoice != nil {
		difference := new(big.Rat).Sub(invoice, charge)
		result.invoiceCompared = true
		result.invoiceDifferenceNumerator, result.invoiceDifferenceDenominator = difference.Num().String(), difference.Denom().String()
	}
	result.complete = true
	return result, nil
}

func capacityMonetaryDecimal(ctx context.Context, value string) (*big.Rat, error) {
	negative := strings.HasPrefix(value, "-")
	unsigned := value
	if negative || strings.HasPrefix(value, "+") {
		unsigned = value[1:]
	}
	amount, err := capacityContractDecimal(ctx, unsigned)
	if err != nil {
		return nil, err
	}
	if negative {
		amount.Neg(amount)
	}
	return amount, nil
}

func capacityContractDecimal(ctx context.Context, value string) (*big.Rat, error) {
	whole, fraction, decimal := strings.Cut(value, ".")
	if whole == "" || decimal && fraction == "" {
		return nil, errCapacityCounterInput
	}
	integer, err := capacityUnsignedInteger(ctx, whole)
	if err != nil {
		return nil, err
	}
	if !decimal {
		return new(big.Rat).SetInt(integer), nil
	}
	for _, digit := range fraction {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if digit < '0' || digit > '9' {
			return nil, errCapacityCounterInput
		}
	}
	// Fractional leading zeros carry precision and must survive parsing.
	digits, ok := new(big.Int).SetString(whole+fraction, 10)
	if !ok {
		return nil, errCapacityCounterInput
	}
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(len(fraction))), nil)
	return new(big.Rat).SetFrac(digits, scale), nil
}

func capacityUnsignedInteger(ctx context.Context, value string) (*big.Int, error) {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return nil, errCapacityCounterInput
	}
	for _, digit := range value {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if digit < '0' || digit > '9' {
			return nil, errCapacityCounterInput
		}
	}
	integer, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil, errCapacityCounterInput
	}
	return integer, nil
}
