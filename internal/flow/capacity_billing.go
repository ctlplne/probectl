// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"math/big"
	"math/bits"
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type capacityBillingMode string

const (
	capacityBillingIn             capacityBillingMode = "in"
	capacityBillingOut            capacityBillingMode = "out"
	capacityBillingMaxPercentiles capacityBillingMode = "max_directional_percentiles"
	capacityBillingIntervalMax    capacityBillingMode = "interval_max"
	capacityBillingIntervalSum    capacityBillingMode = "interval_sum"
)

// These private calculation facts confer no source or circuit membership grant.
// The reader must authorize the complete current member set before supplying a
// common five-minute grid. Unknown samples must be explicit, never zero-filled.
type capacityBillingMember struct {
	tenant, context, router, iface string
	source, incarnation            string
	samples                        []capacityBillingSample
}

type capacityBillingSample struct {
	in, out capacityCounterRate
}

type capacityBillingWindow struct {
	from, to               time.Time
	mode                   capacityBillingMode
	memoryBytes, workUnits int64
}

type capacityBillingPercentile struct {
	tenant                      string
	from, to                    time.Time
	numerator, denominator      string
	expected, observed, missing int
	rank                        int
	complete                    bool
}

// capacityBillingP95 sums distinct circuit members on the common grid BEFORE
// ranking, and makes the directional billing convention explicit. Incomplete
// required coverage never yields a percentile over the surviving population.
func capacityBillingP95(ctx context.Context, window capacityBillingWindow, members []capacityBillingMember) (capacityBillingPercentile, error) {
	none := capacityBillingPercentile{}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return none, tenancy.ErrNoTenant
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	count, err := admitCapacityBilling(ctx, tenant.String(), window, members)
	if err != nil {
		return none, err
	}
	type memberKey struct{ context, router, iface string }
	seen := make(map[memberKey]struct{}, len(members))
	in, out := make([]*big.Rat, count), make([]*big.Rat, count)
	missingIn, missingOut := make([]bool, count), make([]bool, count)
	for i := range count {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		in[i], out[i] = new(big.Rat), new(big.Rat)
	}
	for _, member := range members {
		key := memberKey{member.context, member.router, member.iface}
		if _, duplicate := seen[key]; duplicate {
			return none, errCapacityCounterInput
		}
		seen[key] = struct{}{}
		for i, sample := range member.samples {
			if err := ctx.Err(); err != nil {
				return none, err
			}
			from := window.from.Add(time.Duration(i) * 5 * time.Minute)
			to := from.Add(5 * time.Minute)
			if to.After(window.to) {
				to = window.to
			}
			for direction, rate := range []capacityCounterRate{sample.in, sample.out} {
				value, observed, err := capacityBillingBytes(ctx, rate, from, to)
				if err != nil {
					return none, err
				}
				switch direction {
				case 0:
					if observed {
						in[i].Add(in[i], value)
					} else {
						missingIn[i] = true
					}
				case 1:
					if observed {
						out[i].Add(out[i], value)
					} else {
						missingOut[i] = true
					}
				}
			}
		}
	}
	result := capacityBillingPercentile{tenant: tenant.String(), from: window.from, to: window.to, expected: count}
	for i := range count {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		missing := missingIn[i] || missingOut[i]
		switch window.mode {
		case capacityBillingIn:
			missing = missingIn[i]
		case capacityBillingOut:
			missing = missingOut[i]
		}
		if missing {
			result.missing++
		} else {
			result.observed++
		}
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if result.missing != 0 {
		return result, nil
	}
	inRates, outRates := make([]*big.Rat, count), make([]*big.Rat, count)
	for i := range count {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		from := window.from.Add(time.Duration(i) * 5 * time.Minute)
		elapsed := min(5*time.Minute, window.to.Sub(from))
		scale := new(big.Rat).SetFrac(big.NewInt(8_000_000_000), big.NewInt(int64(elapsed)))
		inRates[i] = new(big.Rat).Mul(in[i], scale)
		outRates[i] = new(big.Rat).Mul(out[i], scale)
	}
	values := inRates
	switch window.mode {
	case capacityBillingOut:
		values = outRates
	case capacityBillingIntervalMax:
		for i := range count {
			if outRates[i].Cmp(inRates[i]) > 0 {
				values[i] = outRates[i]
			}
		}
	case capacityBillingIntervalSum:
		for i := range count {
			values[i] = new(big.Rat).Add(inRates[i], outRates[i])
		}
	}
	// ceil(.95*N), without multiplying a potentially large N by 95.
	result.rank = count - count/20
	sort.Slice(values, func(i, j int) bool { return values[i].Cmp(values[j]) < 0 })
	selected := values[result.rank-1]
	if window.mode == capacityBillingMaxPercentiles {
		sort.Slice(outRates, func(i, j int) bool { return outRates[i].Cmp(outRates[j]) < 0 })
		if other := outRates[result.rank-1]; other.Cmp(selected) > 0 {
			selected = other
		}
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	result.numerator, result.denominator, result.complete = selected.Num().String(), selected.Denom().String(), true
	return result, nil
}

func admitCapacityBilling(ctx context.Context, tenant string, window capacityBillingWindow, members []capacityBillingMember) (int, error) {
	span := window.to.Sub(window.from)
	if window.from.IsZero() || window.to.IsZero() || span <= 0 || !window.from.Add(span).Equal(window.to) || len(members) == 0 {
		return 0, errCapacityCounterInput
	}
	switch window.mode {
	case capacityBillingIn, capacityBillingOut, capacityBillingMaxPercentiles, capacityBillingIntervalMax, capacityBillingIntervalSum:
	default:
		return 0, errCapacityCounterInput
	}
	count := int64(1 + (span-1)/(5*time.Minute))
	memory, work := window.memoryBytes, window.workUnits
	debit := func(n, memoryUnit, workUnit int64) bool {
		if n < 0 || memoryUnit <= 0 || workUnit <= 0 || n > memory/memoryUnit || n > work/workUnit {
			return false
		}
		memory, work = memory-n*memoryUnit, work-n*workUnit
		return true
	}
	if memory < 4096 || work < 4096 || !debit(1, 4096, 4096) || !debit(count, 1024, 512+int64(bits.Len64(uint64(count)))*64) {
		return 0, errCapacityCounterInput
	}
	widestWords := int64(1)
	for _, member := range members {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if member.tenant != tenant || int64(len(member.samples)) != count || !debit(1, 256, 256) {
			return 0, errCapacityCounterInput
		}
		for _, value := range []string{member.tenant, member.context, member.router, member.iface, member.source, member.incarnation} {
			if !debit(int64(len(value)), 16, 16) || value == "" || strings.TrimSpace(value) != value {
				return 0, errCapacityCounterInput
			}
		}
		memberWords := int64(1)
		for _, sample := range member.samples {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			if !debit(1, 512, 512) {
				return 0, errCapacityCounterInput
			}
			for _, rate := range []capacityCounterRate{sample.in, sample.out} {
				// Decimal parsing and rational consistency checks have wide-integer
				// cost, not just string-copy cost. Charge a quadratic word bound
				// before parsing rather than clipping exact counter magnitudes.
				words := int64(1)
				for _, value := range []string{rate.bytes, rate.bytesDenominator, rate.numerator, rate.denominator, rate.reason} {
					if !debit(int64(len(value)), 32, 32) {
						return 0, errCapacityCounterInput
					}
					words += int64(len(value)) / 16
				}
				if words > work/64 || !debit(words, 1, words*64) {
					return 0, errCapacityCounterInput
				}
				memberWords = max(memberWords, words)
			}
		}
		// Distinct fractional denominators can multiply during circuit sums;
		// bound their complete combined width, not only the widest member.
		if memberWords > memory/128 || memberWords > work/128 {
			return 0, errCapacityCounterInput
		}
		widestWords += memberWords
	}
	// Member summation can add log2(member count) bits. Cover comparisons and
	// cross-products of the resulting rational rates throughout both sorts.
	widestWords += int64(bits.Len(uint(len(members))))/64 + 1
	sortWork := int64(bits.Len64(uint64(count))) * 64
	if widestWords > memory/128 || widestWords > work/sortWork || widestWords > work/(sortWork*widestWords) || !debit(count, widestWords*128, sortWork*widestWords*widestWords) {
		return 0, errCapacityCounterInput
	}
	return int(count), nil
}

func capacityBillingBytes(ctx context.Context, rate capacityCounterRate, from, to time.Time) (*big.Rat, bool, error) {
	if !rate.from.Equal(from) || !rate.to.Equal(to) {
		return nil, false, errCapacityCounterInput
	}
	if !rate.observed {
		if rate.reason == "" || rate.bytes != "" || rate.bytesDenominator != "" || rate.numerator != "" || rate.denominator != "" || rate.wrapped {
			return nil, false, errCapacityCounterInput
		}
		return nil, false, nil
	}
	if rate.reason != "" {
		return nil, false, errCapacityCounterInput
	}
	byteDenominator := rate.bytesDenominator
	if byteDenominator == "" {
		byteDenominator = "1"
	}
	values := make([]*big.Int, 0, 4)
	for _, text := range []string{rate.bytes, rate.numerator, rate.denominator, byteDenominator} {
		if text == "" || (len(text) > 1 && text[0] == '0') {
			return nil, false, errCapacityCounterInput
		}
		for _, char := range text {
			if err := ctx.Err(); err != nil {
				return nil, false, err
			}
			if char < '0' || char > '9' {
				return nil, false, errCapacityCounterInput
			}
		}
		value, ok := new(big.Int).SetString(text, 10)
		if !ok {
			return nil, false, errCapacityCounterInput
		}
		values = append(values, value)
	}
	if values[2].Sign() == 0 || values[3].Sign() == 0 {
		return nil, false, errCapacityCounterInput
	}
	left := new(big.Int).Mul(values[1], big.NewInt(int64(to.Sub(from))))
	left.Mul(left, values[3])
	right := new(big.Int).Mul(new(big.Int).Mul(new(big.Int).Set(values[0]), big.NewInt(8_000_000_000)), values[2])
	if left.Cmp(right) != 0 {
		return nil, false, errCapacityCounterInput
	}
	return new(big.Rat).SetFrac(values[0], values[3]), true, nil
}
