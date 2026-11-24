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
)

type FailureTrafficPeak struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	BPS  string    `json:"bps"`
}

type FailureTrafficPortSeries struct {
	FailurePort
	Current          FailureTrafficPortProjection `json:"current"`
	MeasuredPeak     *FailureTrafficPeak          `json:"measured_peak,omitempty"`
	ProjectedPeak    *FailureTrafficPeak          `json:"projected_peak,omitempty"`
	ObservedSamples  int                          `json:"observed_samples"`
	ProjectedSamples int                          `json:"projected_samples"`
	AtCapacity       *bool                        `json:"at_capacity,omitempty"`
	Runout           *CapacityForecastResult      `json:"runout,omitempty"`
	RunoutStatus     string                       `json:"runout_status"`
}

type FailureTrafficSeries struct {
	From            time.Time                  `json:"from"`
	To              time.Time                  `json:"to"`
	Samples         int                        `json:"samples"`
	Complete        bool                       `json:"complete"`
	AffectedBytes   string                     `json:"affected_bytes"`
	ReroutedBytes   string                     `json:"rerouted_bytes"`
	UnroutedBytes   string                     `json:"unrouted_bytes"`
	UnresolvedBytes string                     `json:"unresolved_bytes"`
	Ports           []FailureTrafficPortSeries `json:"ports"`
}

type failureTrafficPeak struct {
	sample *FailureTrafficPeak
	bps    big.Rat
}

func (p *failureTrafficPeak) observe(from, to time.Time, bps *big.Rat) {
	if p.sample == nil || p.bps.Cmp(bps) < 0 {
		p.sample = &FailureTrafficPeak{From: from, To: to, BPS: bps.RatString()}
		p.bps.Set(bps)
	}
}

type failureTrafficSeriesPort struct {
	result             FailureTrafficPortSeries
	measured, expected failureTrafficPeak
	samples            []capacityCounterRate
	stableCapacity     bool
	capacity           string
}

// ProjectFailureTrafficSeries calculates peaks only after applying each
// interval's transfers to that interval's counter baseline. Its optional runout
// uses the same five-minute grid and weekly model as measured capacity.
func ProjectFailureTrafficSeries(ctx context.Context, samples []FailureTrafficSample, until time.Time, memoryBytes, workUnits int64) (FailureTrafficSeries, error) {
	const bucket = 5 * time.Minute
	none := FailureTrafficSeries{}
	if len(samples) == 0 || len(samples[0].Baselines) == 0 {
		return none, ErrFailureTrafficInput
	}
	from, to := samples[0].From.UTC(), samples[len(samples)-1].To.UTC()
	span := to.Sub(from)
	if from.IsZero() || span <= 0 || !from.Add(span).Equal(to) ||
		int64(len(samples)) != int64(1+(span-1)/bucket) || !until.IsZero() && !until.After(to) {
		return none, ErrFailureTrafficInput
	}
	portCount := int64(len(samples[0].Baselines))
	budget := capacityGridAdmission{memory: memoryBytes / 2, work: workUnits / 2}
	if !budget.debit(portCount, 2048, 2048) ||
		!budget.debit(int64(len(samples)), 512, 512) {
		return none, ErrFailureTrafficBudget
	}
	ports := make([]failureTrafficSeriesPort, len(samples[0].Baselines))
	var totals [4]big.Rat
	out := FailureTrafficSeries{From: from, To: to, Complete: true, Samples: len(samples)}
	forecastEligible := !until.IsZero() && len(samples) >= capacityWeeklyPhases*2
	for i, raw := range samples {
		start := from.Add(time.Duration(i) * bucket)
		if !raw.From.Equal(start) || !raw.To.Equal(start.Add(min(bucket, to.Sub(start)))) {
			return none, ErrFailureTrafficInput
		}
		sample, err := projectFailureTrafficSample(ctx, raw, &budget)
		if err != nil {
			return none, err
		}
		if raw.TenantID != samples[0].TenantID || len(sample.Ports) != len(ports) {
			return none, ErrFailureTrafficInput
		}
		out.Complete = out.Complete && sample.Complete
		spanOctets := big.NewRat(int64(sample.To.Sub(sample.From)), 8_000_000_000)
		for j, text := range []string{sample.AffectedBPS, sample.ReroutedBPS, sample.UnroutedBPS, sample.UnresolvedBPS} {
			bps, ok := new(big.Rat).SetString(text)
			if !ok || !budget.arithmetic(&totals[j], bps, spanOctets) {
				return none, ErrFailureTrafficBudget
			}
			totals[j].Add(&totals[j], bps.Mul(bps, spanOctets))
		}
		for j, row := range sample.Ports {
			port := &ports[j]
			if i == 0 {
				port.result.FailurePort, port.capacity, port.stableCapacity = row.FailurePort, row.CapacityBPS, row.CapacityBPS != ""
			} else if row.FailurePort != port.result.FailurePort || (row.Status == "failed") != (port.result.Current.Status == "failed") {
				return none, ErrFailureTrafficInput
			}
			if err := port.observe(sample.From, sample.To, row, spanOctets, forecastEligible, &budget); err != nil {
				return none, err
			}
		}
	}
	out.AffectedBytes, out.ReroutedBytes = totals[0].RatString(), totals[1].RatString()
	out.UnroutedBytes, out.UnresolvedBytes = totals[2].RatString(), totals[3].RatString()
	out.Ports = make([]FailureTrafficPortSeries, 0, len(ports))
	for _, port := range ports {
		result, err := port.finish(ctx, samples[0].TenantID, out, until, memoryBytes/2/portCount, workUnits/2/portCount)
		if err != nil {
			return none, err
		}
		out.Ports = append(out.Ports, result)
	}
	return out, ctx.Err()
}

func (port *failureTrafficSeriesPort) observe(from, to time.Time, row FailureTrafficPortProjection, spanOctets *big.Rat, forecastEligible bool, budget *capacityGridAdmission) error {
	port.result.Current = row
	port.stableCapacity = port.stableCapacity && row.CapacityBPS == port.capacity
	if row.MeasuredBPS != "" {
		measured, ok := new(big.Rat).SetString(row.MeasuredBPS)
		if !ok || !budget.arithmetic(measured, &port.measured.bps) {
			return ErrFailureTrafficBudget
		}
		port.measured.observe(from, to, measured)
		port.result.ObservedSamples++
	}
	if row.ProjectedBPS == "" {
		return nil
	}
	projected, ok := new(big.Rat).SetString(row.ProjectedBPS)
	if !ok || !budget.arithmetic(projected, &port.expected.bps) {
		return ErrFailureTrafficBudget
	}
	port.expected.observe(from, to, projected)
	port.result.ProjectedSamples++
	if forecastEligible && port.stableCapacity {
		if !budget.debit(1, 1024, 1024) || !budget.arithmetic(projected, spanOctets) {
			return ErrFailureTrafficBudget
		}
		octets := new(big.Rat).Mul(projected, spanOctets)
		port.samples = append(port.samples, capacityCounterRate{from: from, to: to,
			bytes: octets.Num().String(), bytesDenominator: octets.Denom().String(),
			numerator: projected.Num().String(), denominator: projected.Denom().String(), observed: true})
	}
	return nil
}

func (port *failureTrafficSeriesPort) finish(ctx context.Context, tenant string, series FailureTrafficSeries, until time.Time, memory, work int64) (FailureTrafficPortSeries, error) {
	out := port.result
	if out.ObservedSamples == series.Samples {
		out.MeasuredPeak = port.measured.sample
	}
	if out.ProjectedSamples == series.Samples {
		out.ProjectedPeak = port.expected.sample
	}
	if out.Current.UtilizationRatio != "" {
		ratio, ok := new(big.Rat).SetString(out.Current.UtilizationRatio)
		if !ok {
			return FailureTrafficPortSeries{}, ErrFailureTrafficInput
		}
		atCapacity := ratio.Cmp(big.NewRat(1, 1)) >= 0
		out.AtCapacity = &atCapacity
	}
	switch {
	case out.Current.Status == "failed":
		out.RunoutStatus = "failed"
	case until.IsZero():
		out.RunoutStatus = "horizon_absent"
	case !port.stableCapacity:
		out.RunoutStatus = "stable_capacity_unavailable"
	case out.ProjectedSamples != series.Samples:
		out.RunoutStatus = "projected_coverage_incomplete"
	case len(port.samples) < capacityWeeklyPhases*2:
		out.RunoutStatus = "weekly_repetitions_missing"
	default:
		forecast, err := forecastCapacity(ctx, capacityForecastInput{tenant: tenant, target: out.InterfaceID, capacityBPS: port.capacity,
			from: series.From, to: series.To, until: until, samples: port.samples, memoryBytes: memory, workUnits: work})
		if err != nil {
			return FailureTrafficPortSeries{}, err
		}
		projected := projectCapacityForecast(forecast, out.Direction)
		out.Runout, out.RunoutStatus = &projected, projected.Reason
		if projected.Trained {
			out.RunoutStatus = "forecast"
		}
	}
	return out, ctx.Err()
}
