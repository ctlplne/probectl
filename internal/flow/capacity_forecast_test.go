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
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func capacityForecastTestRate(from time.Time, y *big.Rat) capacityCounterRate {
	// A five-minute mean of y bps carries exactly y*300/8 octets.
	bytes := new(big.Rat).Mul(y, big.NewRat(75, 2))
	return capacityCounterRate{from: from, to: from.Add(5 * time.Minute), bytes: bytes.Num().String(), bytesDenominator: bytes.Denom().String(), numerator: y.Num().String(), denominator: y.Denom().String(), observed: true}
}

func capacityForecastFixture(tenant string, weeks int, base int64, growth, noise bool) capacityForecastInput {
	from := time.Date(2026, 10, 1, 0, 0, 0, 123456789, time.UTC)
	input := capacityForecastInput{tenant: tenant, target: "owned interface/circuit selection", capacityBPS: "1000", from: from, to: from.Add(time.Duration(weeks*capacityWeeklyPhases) * 5 * time.Minute), memoryBytes: 512 << 20, workUnits: 16 << 30}
	input.until = input.to.Add(3 * 24 * time.Hour)
	for i := range weeks * capacityWeeklyPhases {
		value := new(big.Rat).SetInt64(base + int64((i%capacityWeeklyPhases)/(24*12))*20)
		if growth {
			value.Add(value, big.NewRat(int64(i), 7))
		}
		if noise {
			value.Add(value, big.NewRat([]int64{0, 2, -2}[i/capacityWeeklyPhases%3], 1))
		}
		input.samples = append(input.samples, capacityForecastTestRate(from.Add(time.Duration(i)*5*time.Minute), value))
	}
	return input
}

func TestCapacityForecastKeepsExactWideTrendWeeklyPatternAndHandRunout(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		const base int64 = 9007199254740993
		input := capacityForecastFixture(tenant, 2, base, true, false)
		input.capacityBPS = big.NewInt(base + 578).String()
		got, err := forecastCapacity(ctx, input)
		want := input.to.Add(70 * time.Minute) // i=4046; 4046/7=578, on weekday phase zero.
		if err != nil || !got.trained || !got.coverageComplete || got.observed != 4032 || got.expected != 4032 || got.trendNumerator != "288" || got.trendDenominator != "7" || got.tenant != tenant || got.target != input.target || got.reason != "" {
			t.Fatal("forecast lost exact wide rates, weekly trend or tenant", got, err)
		}
		if got.model != "weighted_linear_weekly_5m_v1" || got.intervalMethod != "in_sample_residual_envelope" {
			t.Fatal("forecast did not identify its model and interval method", got)
		}
		for _, window := range []capacityRunoutWindow{got.earliest, got.central, got.latest} {
			if !window.reached || !window.from.Equal(want) || !window.to.Equal(want.Add(5*time.Minute)) {
				t.Fatal("known growth runout missed its five-minute hand oracle", window, want)
			}
		}
	}
}

func TestCapacityForecastReportsResidualEnvelopeAndCensoredHorizon(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	noisy := capacityForecastFixture("red", 3, 100, true, true)
	got, err := forecastCapacity(ctx, noisy)
	if err != nil || !got.trained || !got.central.reached || !got.earliest.reached || !got.latest.reached || got.central.from.Before(got.earliest.from) || got.latest.from.Before(got.central.from) || !got.latest.from.After(got.earliest.from) {
		t.Fatal("forecast omitted or inverted its empirical residual interval", got, err)
	}
	flat := capacityForecastFixture("red", 2, 100, false, false)
	flat.capacityBPS = "200"
	got, err = forecastCapacity(ctx, flat)
	if err != nil || !got.trained || got.trendNumerator != "0" || got.central.reached || got.earliest.reached || got.latest.reached || got.reason != "threshold_not_reached_in_horizon" || !got.lastSampleKnown || !got.lastSampleExceeded || got.observedExceedances != 1152 || got.capacityNumerator != "200" || got.capacityDenominator != "1" {
		t.Fatal("flat weekly load invented a runout beyond observed evidence", got, err)
	}
}

func TestCapacityForecastWithholdsMissingTrainingAndWeeklyRepetitions(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	input := capacityForecastFixture("red", 1, 100, true, false)
	got, err := forecastCapacity(ctx, input)
	if err != nil || got.trained || !got.coverageComplete || got.reason != "weekly_repetitions_missing" || got.central.reached || got.trendNumerator != "" {
		t.Fatal("single-week history claimed an identified weekly forecast", got, err)
	}
	input = capacityForecastFixture("red", 2, 100, true, false)
	old := input.samples[100]
	input.samples[100] = capacityCounterRate{from: old.from, to: old.to, reason: "counter_poll_gap"}
	got, err = forecastCapacity(ctx, input)
	if err != nil || got.trained || got.coverageComplete || got.expected != 4032 || got.observed != 4031 || got.reason != "training_coverage_incomplete" || got.central.reached || got.trendNumerator != "" {
		t.Fatal("forecast shortened training or zero-filled a missing poll", got, err)
	}
}

func TestCapacityForecastRequiresTenantAndWholeOperationAdmission(t *testing.T) {
	input := capacityForecastFixture("red", 2, 100, true, false)
	if got, err := forecastCapacity(t.Context(), input); !errors.Is(err, tenancy.ErrNoTenant) || !reflect.DeepEqual(got, capacityForecast{}) {
		t.Fatal("forecast calculation preceded its tenant boundary", got, err)
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	for _, scenario := range []string{"foreign tenant", "memory", "work", "canceled"} {
		altered := input
		bound := ctx
		switch scenario {
		case "foreign tenant":
			altered.tenant = "blue"
		case "memory":
			altered.memoryBytes = 1
		case "work":
			altered.workUnits = 1
		case "canceled":
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			bound = canceled
		}
		if got, err := forecastCapacity(bound, altered); err == nil || !reflect.DeepEqual(got, capacityForecast{}) {
			t.Fatal("foreign/unadmitted forecast returned a successful prefix", scenario, got, err)
		}
	}
}

func TestCapacityForecastThresholdRequiresExactPositiveTenantBoundedArithmetic(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	value := "9007199254740993.000000000000000001"
	if err := ValidateCapacityForecastThreshold(ctx, value, 1<<20, 1<<20); err != nil {
		t.Fatal("exact wide threshold was narrowed", err)
	}
	for _, value := range []string{"0", "-1", "1/3", "1e20", "01", "1.", "1.x"} {
		if err := ValidateCapacityForecastThreshold(ctx, value, 1<<20, 1<<20); err == nil {
			t.Fatal("unsupported or nonpositive threshold was admitted", value)
		}
	}
	if err := ValidateCapacityForecastThreshold(t.Context(), "1", 1<<20, 1<<20); !errors.Is(err, tenancy.ErrNoTenant) {
		t.Fatal("threshold parsed before tenant boundary", err)
	}
	if err := ValidateCapacityForecastThreshold(ctx, value, 1, 1<<20); err == nil {
		t.Fatal("unadmitted memory was accepted")
	}
	if err := ValidateCapacityForecastThreshold(ctx, value, 1<<20, 1); err == nil {
		t.Fatal("unadmitted arithmetic was accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := ValidateCapacityForecastThreshold(canceled, value, 1<<20, 1<<20); err == nil {
		t.Fatal("canceled threshold computation was accepted")
	}
	for _, memory := range []int64{0, -1, int64(^uint64(0) >> 1)} {
		if work, err := CapacityForecastWorkUnits(memory); err == nil || work != 0 {
			t.Fatal("unbounded or overflowing work admission was accepted", work, err)
		}
	}
}
