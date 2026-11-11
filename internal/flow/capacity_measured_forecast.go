// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"math/big"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type CapacityRunoutInterval struct {
	Reached bool       `json:"reached"`
	From    *time.Time `json:"from,omitempty"`
	To      *time.Time `json:"to,omitempty"`
}

type CapacityForecastResult struct {
	Target              string                 `json:"target"`
	Direction           string                 `json:"direction"`
	CounterModel        string                 `json:"counter_model"`
	Model               string                 `json:"model"`
	IntervalMethod      string                 `json:"interval_method"`
	From                time.Time              `json:"from"`
	To                  time.Time              `json:"to"`
	Until               time.Time              `json:"until"`
	ExpectedSamples     int                    `json:"expected_samples"`
	ObservedSamples     int                    `json:"observed_samples"`
	CoverageComplete    bool                   `json:"coverage_complete"`
	Trained             bool                   `json:"trained"`
	Reason              string                 `json:"reason,omitempty"`
	CapacityNumerator   string                 `json:"capacity_numerator"`
	CapacityDenominator string                 `json:"capacity_denominator"`
	TrendNumerator      string                 `json:"trend_bps_per_day_numerator,omitempty"`
	TrendDenominator    string                 `json:"trend_bps_per_day_denominator,omitempty"`
	ObservedExceedances int                    `json:"observed_exceedances"`
	LastSampleKnown     bool                   `json:"last_sample_known"`
	LastSampleExceeded  bool                   `json:"last_sample_exceeded"`
	Central             CapacityRunoutInterval `json:"central"`
	Earliest            CapacityRunoutInterval `json:"earliest"`
	Latest              CapacityRunoutInterval `json:"latest"`
}

// ForecastCapacityMeasured fits the existing exact trend/weekly model to the
// same member sums as billing. The operator's forecast threshold is separate
// from the physical wrap bounds and financial commit. For max directional
// percentiles, both directional forecasts are returned explicitly: a maximum
// of two period percentiles is not an interval-max traffic time series.
func ForecastCapacityMeasured(ctx context.Context, window CapacityMeasurementWindow, target, direction, capacityBPS string, until time.Time, members []CapacityMeasuredMember) ([]CapacityForecastResult, error) {
	tenant, bound := tenancy.FromContext(ctx)
	if !bound {
		return nil, tenancy.ErrNoTenant
	}
	if !until.After(window.To) {
		return nil, errCapacityCounterInput
	}
	inputWindow := window
	inputWindow.MemoryBytes, inputWindow.WorkUnits = window.MemoryBytes/2, window.WorkUnits/2
	inputs, err := measuredCapacityBillingInputs(ctx, inputWindow, members)
	if err != nil {
		return nil, err
	}
	billingWindow := capacityBillingWindow{from: window.From, to: window.To, mode: capacityBillingMode(direction), memoryBytes: window.MemoryBytes / 4, workUnits: window.WorkUnits / 4}
	count, err := admitCapacityBilling(ctx, tenant.String(), billingWindow, inputs)
	if err != nil {
		return nil, err
	}
	totals, err := sumCapacityBillingMembers(ctx, billingWindow, inputs, count)
	if err != nil {
		return nil, err
	}
	directions := []string{direction}
	if direction == string(capacityBillingMaxPercentiles) {
		directions = []string{"in", "out"}
	}
	results := make([]CapacityForecastResult, 0, len(directions))
	for _, selected := range directions {
		samples, err := measuredCapacityForecastSamples(ctx, window, totals, selected)
		if err != nil {
			return nil, err
		}
		forecast, err := forecastCapacity(ctx, capacityForecastInput{tenant: tenant.String(), target: target, capacityBPS: capacityBPS, from: window.From, to: window.To,
			until: until, samples: samples, memoryBytes: window.MemoryBytes / 4, workUnits: window.WorkUnits / 4})
		if err != nil {
			return nil, err
		}
		results = append(results, projectCapacityForecast(forecast, selected))
	}
	return results, ctx.Err()
}

func measuredCapacityForecastSamples(ctx context.Context, window CapacityMeasurementWindow, totals capacityBillingTotals, direction string) ([]capacityCounterRate, error) {
	budget := capacityGridAdmission{window.MemoryBytes / 8, window.WorkUnits / 16}
	if !budget.debit(int64(len(totals.in)), 1024, 1024) {
		return nil, errCapacityCounterInput
	}
	samples := make([]capacityCounterRate, len(totals.in))
	for i := range samples {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		from := window.From.Add(time.Duration(i) * 5 * time.Minute)
		to := from.Add(min(5*time.Minute, window.To.Sub(from)))
		samples[i] = capacityCounterRate{from: from, to: to, reason: "member_counter_coverage_incomplete"}
		missing, value := false, totals.in[i]
		switch capacityBillingMode(direction) {
		case capacityBillingIn:
			missing = totals.missingIn[i]
		case capacityBillingOut:
			missing, value = totals.missingOut[i], totals.out[i]
		case capacityBillingIntervalMax:
			missing = totals.missingIn[i] || totals.missingOut[i]
			if totals.out[i].Cmp(value) > 0 {
				value = totals.out[i]
			}
		case capacityBillingIntervalSum:
			missing = totals.missingIn[i] || totals.missingOut[i]
			if !budget.arithmetic(totals.in[i], totals.out[i]) {
				return nil, errCapacityCounterInput
			}
			value = new(big.Rat).Add(totals.in[i], totals.out[i])
		default:
			return nil, errCapacityCounterInput
		}
		if missing {
			continue
		}
		if !budget.arithmetic(value) {
			return nil, errCapacityCounterInput
		}
		rate := new(big.Rat).Mul(value, new(big.Rat).SetFrac(big.NewInt(8_000_000_000), big.NewInt(int64(to.Sub(from)))))
		samples[i] = capacityCounterRate{from: from, to: to, bytes: value.Num().String(), bytesDenominator: value.Denom().String(), numerator: rate.Num().String(), denominator: rate.Denom().String(), observed: true}
	}
	return samples, nil
}

func projectCapacityRunout(in capacityRunoutWindow) CapacityRunoutInterval {
	if !in.reached {
		return CapacityRunoutInterval{}
	}
	return CapacityRunoutInterval{Reached: true, From: &in.from, To: &in.to}
}

func projectCapacityForecast(in capacityForecast, direction string) CapacityForecastResult {
	return CapacityForecastResult{Target: in.target, Direction: direction, CounterModel: CapacityCounterWindowModel(), Model: in.model, IntervalMethod: in.intervalMethod,
		From: in.from, To: in.to, Until: in.until, ExpectedSamples: in.expected, ObservedSamples: in.observed, CoverageComplete: in.coverageComplete, Trained: in.trained, Reason: in.reason,
		CapacityNumerator: in.capacityNumerator, CapacityDenominator: in.capacityDenominator, TrendNumerator: in.trendNumerator, TrendDenominator: in.trendDenominator,
		ObservedExceedances: in.observedExceedances, LastSampleKnown: in.lastSampleKnown, LastSampleExceeded: in.lastSampleExceeded,
		Central: projectCapacityRunout(in.central), Earliest: projectCapacityRunout(in.earliest), Latest: projectCapacityRunout(in.latest)}
}
