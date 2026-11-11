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

	"github.com/ctlplne/probectl/internal/tenancy"
)

const capacityWeeklyPhases = 7 * 24 * 12

type capacityForecastInput struct {
	tenant, target, capacityBPS string
	from, to, until             time.Time
	samples                     []capacityCounterRate
	memoryBytes, workUnits      int64
}

type capacityRunoutWindow struct {
	from, to time.Time
	reached  bool
}

type capacityForecast struct {
	tenant, target, model, intervalMethod, reason string
	from, to, until                               time.Time
	expected, observed                            int
	coverageComplete, trained                     bool
	capacityNumerator, capacityDenominator        string
	observedExceedances                           int
	lastSampleKnown, lastSampleExceeded           bool
	trendNumerator, trendDenominator              string // Exact bps/day, including a negative trend.
	central, earliest, latest                     capacityRunoutWindow
}

type capacityForecastPhase struct {
	count                        int
	weight, x, y, xx, xy, offset big.Rat
}

// Forecasts use complete already-authorized counter grids. The private target
// is provenance, never a read grant. Time-weighted least squares fits one trend
// plus all 2016 weekly five-minute phases, anchored to the original UTC grid.
// Two repetitions of every phase are required, not an arbitrary history cap.
// The interval is the in-sample residual envelope, not a calibrated confidence
// claim. A runout window identifies the first future interval whose modeled
// mean reaches the operator's capacity threshold; it asserts no within-poll
// crossing time or remediation action.
func forecastCapacity(ctx context.Context, input capacityForecastInput) (capacityForecast, error) {
	none := capacityForecast{}
	budget, capacity, err := admitCapacityForecast(ctx, input)
	if err != nil {
		return none, err
	}
	result := capacityForecast{tenant: input.tenant, target: input.target, model: "weighted_linear_weekly_5m_v1", intervalMethod: "in_sample_residual_envelope", from: input.from, to: input.to, until: input.until, expected: len(input.samples), capacityNumerator: capacity.Num().String(), capacityDenominator: capacity.Denom().String()}
	phases := make([]capacityForecastPhase, capacityWeeklyPhases)
	for i, sample := range input.samples {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		from := input.from.Add(time.Duration(i) * 5 * time.Minute)
		to := from.Add(min(5*time.Minute, input.to.Sub(from)))
		bytes, known, err := capacityBillingBytes(ctx, sample, from, to)
		if err != nil {
			return none, err
		}
		if !known {
			continue
		}
		result.observed++
		y := new(big.Rat).Mul(bytes, new(big.Rat).SetFrac(big.NewInt(8_000_000_000), big.NewInt(int64(to.Sub(from)))))
		x := capacityForecastMidpoint(input.from, from, to)
		weight := new(big.Rat).SetFrac(big.NewInt(int64(to.Sub(from))), big.NewInt(int64(5*time.Minute)))
		p := &phases[i%capacityWeeklyPhases]
		if !budget.arithmetic(&p.weight, &p.x, &p.y, &p.xx, &p.xy, x, y, weight, capacity) {
			return none, errCapacityCounterInput
		}
		exceeded := y.Cmp(capacity) >= 0
		if exceeded {
			result.observedExceedances++
		}
		if i == len(input.samples)-1 {
			result.lastSampleKnown, result.lastSampleExceeded = true, exceeded
		}
		p.count++
		p.weight.Add(&p.weight, weight)
		p.x.Add(&p.x, new(big.Rat).Mul(weight, x))
		p.y.Add(&p.y, new(big.Rat).Mul(weight, y))
		p.xx.Add(&p.xx, new(big.Rat).Mul(weight, new(big.Rat).Mul(x, x)))
		p.xy.Add(&p.xy, new(big.Rat).Mul(weight, new(big.Rat).Mul(x, y)))
	}
	if result.observed != result.expected {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		result.reason = "training_coverage_incomplete"
		return result, nil
	}
	result.coverageComplete = true
	for i := range phases {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if phases[i].count < 2 {
			result.reason = "weekly_repetitions_missing"
			return result, nil
		}
	}
	slope, err := fitCapacityForecast(ctx, phases, &budget)
	if err != nil {
		return none, err
	}
	low, high, err := capacityForecastResiduals(ctx, input, phases, slope, &budget)
	if err != nil {
		return none, err
	}
	perDay := new(big.Rat).Mul(slope, big.NewRat(24*12, 1))
	result.trendNumerator, result.trendDenominator = perDay.Num().String(), perDay.Denom().String()
	if err := predictCapacityRunout(ctx, input, phases, slope, capacity, low, high, &budget, &result); err != nil {
		return none, err
	}
	result.trained = true
	if !result.central.reached {
		result.reason = "threshold_not_reached_in_horizon"
	} else if !result.latest.reached {
		result.reason = "latest_not_reached_in_horizon"
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return result, nil
}

func admitCapacityForecast(ctx context.Context, input capacityForecastInput) (capacityGridAdmission, *big.Rat, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return capacityGridAdmission{}, nil, tenancy.ErrNoTenant
	}
	if err := ctx.Err(); err != nil {
		return capacityGridAdmission{}, nil, err
	}
	span, whole := input.to.Sub(input.from), input.until.Sub(input.from)
	if input.tenant != tenant.String() || input.target == "" || strings.TrimSpace(input.target) != input.target || input.from.IsZero() || span <= 0 || !input.from.Add(span).Equal(input.to) || !input.until.After(input.to) || whole <= 0 || !input.from.Add(whole).Equal(input.until) || int64(len(input.samples)) != int64(1+(span-1)/(5*time.Minute)) {
		return capacityGridAdmission{}, nil, errCapacityCounterInput
	}
	budget := capacityGridAdmission{input.memoryBytes, input.workUnits}
	if !budget.debit(1, 8192, 8192) || !budget.debit(capacityWeeklyPhases, 4096, 4096) || !budget.debit(int64(len(input.samples)), 4096, 4096) {
		return capacityGridAdmission{}, nil, errCapacityCounterInput
	}
	for _, text := range []string{input.tenant, input.target, input.capacityBPS} {
		if !budget.debit(int64(len(text)), 128, 128) {
			return capacityGridAdmission{}, nil, errCapacityCounterInput
		}
	}
	for _, sample := range input.samples {
		if err := ctx.Err(); err != nil {
			return capacityGridAdmission{}, nil, err
		}
		words := int64(1)
		for _, text := range []string{sample.bytes, sample.bytesDenominator, sample.numerator, sample.denominator, sample.reason} {
			if !budget.debit(int64(len(text)), 128, 128) {
				return capacityGridAdmission{}, nil, errCapacityCounterInput
			}
			words += int64(len(text))/16 + 1
		}
		if words > budget.work/512 || words > (budget.work/512)/words || !budget.debit(words, 128, words*512) {
			return capacityGridAdmission{}, nil, errCapacityCounterInput
		}
	}
	words := int64(len(input.capacityBPS))/8 + 1
	if words > budget.work/512 || words > (budget.work/512)/words || !budget.debit(words, 128, words*512) {
		return capacityGridAdmission{}, nil, errCapacityCounterInput
	}
	capacity, err := capacityContractDecimal(ctx, input.capacityBPS)
	if err != nil || capacity.Sign() <= 0 {
		return capacityGridAdmission{}, nil, errCapacityCounterInput
	}
	return budget, capacity, nil
}

func capacityForecastMidpoint(anchor, from, to time.Time) *big.Rat {
	n := new(big.Int).Lsh(big.NewInt(int64(from.Sub(anchor))), 1)
	n.Add(n, big.NewInt(int64(to.Sub(from))))
	return new(big.Rat).SetFrac(n, big.NewInt(int64(10*time.Minute)))
}

func fitCapacityForecast(ctx context.Context, phases []capacityForecastPhase, budget *capacityGridAdmission) (*big.Rat, error) {
	var xx, xy big.Rat
	for i := range phases {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p := &phases[i]
		if !budget.arithmetic(&xx, &xy, &p.x, &p.y, &p.xx, &p.xy, &p.weight) {
			return nil, errCapacityCounterInput
		}
		withinXX := new(big.Rat).Sub(&p.xx, new(big.Rat).Quo(new(big.Rat).Mul(&p.x, &p.x), &p.weight))
		withinXY := new(big.Rat).Sub(&p.xy, new(big.Rat).Quo(new(big.Rat).Mul(&p.x, &p.y), &p.weight))
		xx.Add(&xx, withinXX)
		xy.Add(&xy, withinXY)
	}
	if xx.Sign() <= 0 {
		return nil, errCapacityCounterInput
	}
	slope := new(big.Rat).Quo(&xy, &xx)
	for i := range phases {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p := &phases[i]
		if !budget.arithmetic(slope, &p.x, &p.y, &p.weight) {
			return nil, errCapacityCounterInput
		}
		p.offset.Quo(new(big.Rat).Sub(&p.y, new(big.Rat).Mul(slope, &p.x)), &p.weight)
	}
	return slope, nil
}

func capacityForecastResiduals(ctx context.Context, input capacityForecastInput, phases []capacityForecastPhase, slope *big.Rat, budget *capacityGridAdmission) (*big.Rat, *big.Rat, error) {
	low, high := new(big.Rat), new(big.Rat)
	for i, sample := range input.samples {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		x := capacityForecastMidpoint(input.from, sample.from, sample.to)
		y := new(big.Rat)
		if _, ok := y.SetString(sample.numerator + "/" + sample.denominator); !ok {
			return nil, nil, errCapacityCounterInput
		}
		offset := &phases[i%capacityWeeklyPhases].offset
		if !budget.arithmetic(x, y, slope, offset, low, high) {
			return nil, nil, errCapacityCounterInput
		}
		residual := new(big.Rat).Sub(y, new(big.Rat).Add(new(big.Rat).Mul(slope, x), offset))
		if residual.Cmp(low) < 0 {
			low.Set(residual)
		}
		if residual.Cmp(high) > 0 {
			high.Set(residual)
		}
	}
	return low, high, nil
}

func predictCapacityRunout(ctx context.Context, input capacityForecastInput, phases []capacityForecastPhase, slope, capacity, low, high *big.Rat, budget *capacityGridAdmission, result *capacityForecast) error {
	for from := input.to; from.Before(input.until); {
		if err := ctx.Err(); err != nil {
			return err
		}
		elapsed := from.Sub(input.from)
		to := from.Add(min(5*time.Minute-elapsed%(5*time.Minute), input.until.Sub(from)))
		x := capacityForecastMidpoint(input.from, from, to)
		offset := &phases[int(elapsed/(5*time.Minute))%capacityWeeklyPhases].offset
		if !budget.arithmetic(x, offset, slope, capacity, low, high) {
			return errCapacityCounterInput
		}
		mean := new(big.Rat).Add(new(big.Rat).Mul(slope, x), offset)
		for _, scenario := range []struct {
			residual *big.Rat
			window   *capacityRunoutWindow
		}{{new(big.Rat), &result.central}, {high, &result.earliest}, {low, &result.latest}} {
			if !scenario.window.reached && new(big.Rat).Add(mean, scenario.residual).Cmp(capacity) >= 0 {
				*scenario.window = capacityRunoutWindow{from: from, to: to, reached: true}
			}
		}
		if result.central.reached && result.earliest.reached && result.latest.reached {
			break
		}
		from = to
	}
	return ctx.Err()
}
