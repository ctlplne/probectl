// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"context"
	"sort"
	"time"
)

// ExactSeasonalFeature uses Feature's existing tenant and series identities.
// Its measure is an original decimal value from the flow engine.
type ExactSeasonalFeature struct {
	Feature
	Decimal string
}

type ExactSeasonalComparison struct {
	State          SeasonalState
	ComparableDays int
	Calendar       *SeasonalEvidence
	Band           *SeasonalDecimalBand
	TrainingWindow TrainingWindow
	Citations      []Citation
}

func (m WeeklySeasonalModel) CompareDecimalSeries(ctx context.Context, tenant string, latest ExactSeasonalFeature, previous []ExactSeasonalFeature, sensitivity float64, work int64) (ExactSeasonalComparison, error) {
	var result ExactSeasonalComparison
	if tenant == "" {
		return result, ErrNoTenant
	}
	if canCompare := m.location != nil && !latest.TS.IsZero() && latest.Subject != "" && latest.Metric != ""; !canCompare {
		return result, ErrSeasonalDecimal
	}
	if latest.TenantID != tenant {
		return result, ErrCrossTenantFeature
	}
	for _, input := range previous {
		if input.TenantID != tenant {
			return result, ErrCrossTenantFeature
		}
		if !sameDecimalSeries(input.Feature, latest.Feature) {
			return result, ErrSeasonalDecimal
		}
	}
	slot := latest.TS.In(m.location)
	if m.holidays[slot.Format(time.DateOnly)] {
		result.State = SeasonalExcluded
		return result, ctx.Err()
	}
	features, days, err := m.decimalTrainingDates(ctx, slot, previous, work)
	if err != nil {
		return result, err
	}
	result.ComparableDays = len(days)
	if len(days) < m.minimumDays {
		result.State = SeasonalWarming
		return result, ctx.Err()
	}
	state, band, err := compareSeasonalDecimals(ctx, latest.Decimal, days, m.minimumDeviation, sensitivity, work)
	if err != nil {
		return ExactSeasonalComparison{}, err
	}
	return finishDecimalSeason(latest.Feature, slot, features, days, state, band), nil
}

func sameDecimalSeries(a, b Feature) bool {
	return a.Plane == b.Plane && a.Source == b.Source && a.Subject == b.Subject && a.Metric == b.Metric
}

func (m WeeklySeasonalModel) decimalTrainingDates(ctx context.Context, slot time.Time, inputs []ExactSeasonalFeature, work int64) ([]Feature, map[string][]string, error) {
	if int64(len(inputs)) > work {
		return nil, nil, ErrSeasonalDecimal
	}
	dates := make(map[string][]string)
	seen := make(map[time.Time]bool, len(inputs))
	features := make([]Feature, 0, len(inputs))
	currentDate := slot.Format(time.DateOnly)
	for _, input := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		at := input.TS.UTC()
		if at.IsZero() || !at.Before(slot) || seen[at] {
			return nil, nil, ErrSeasonalDecimal
		}
		seen[at] = true
		clock := at.In(m.location)
		date := clock.Format(time.DateOnly)
		if clock.Weekday() != slot.Weekday() || clock.Hour() != slot.Hour() || date == currentDate || m.holidays[date] {
			continue
		}
		dates[date] = append(dates[date], input.Decimal)
		features = append(features, input.Feature)
	}
	sort.Slice(features, func(i, j int) bool { return features[i].TS.Before(features[j].TS) })
	return features, dates, ctx.Err()
}

func finishDecimalSeason(current Feature, slot time.Time, training []Feature, dates map[string][]string, state SeasonalState, band SeasonalDecimalBand) ExactSeasonalComparison {
	ordered := make([]string, 0, len(dates))
	for date := range dates {
		ordered = append(ordered, date)
	}
	sort.Strings(ordered)
	return ExactSeasonalComparison{
		State: state, ComparableDays: len(dates), Band: &band,
		Calendar:       &SeasonalEvidence{Timezone: slot.Location().String(), Weekday: slot.Weekday(), Hour: slot.Hour(), TrainingDays: ordered},
		TrainingWindow: TrainingWindow{Start: training[0].TS, End: training[len(training)-1].TS, Samples: len(training)},
		Citations:      append(currentCitation(current), trainingCitations(training)...),
	}
}
