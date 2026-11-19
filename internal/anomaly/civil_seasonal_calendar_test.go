// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"errors"
	"testing"
	"time"
)

func TestSeasonalCadenceReachesPublishedWarmupCheckpoints(t *testing.T) {
	start := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		cadence     SeasonalCadence
		elapsed     time.Duration
		periods     int
		provisional bool
	}{
		{"hourly cold", SeasonalHourly, 2 * time.Hour, 0, false},
		{"hourly three hours", SeasonalHourly, 3 * time.Hour, 3, false},
		{"hourly five hours", SeasonalHourly, 5 * time.Hour, 5, false},
		{"daily cold", SeasonalDaily, 25 * time.Hour, 0, false},
		{"daily sixty hours", SeasonalDaily, 60 * time.Hour, 2, true},
		{"daily mature", SeasonalDaily, 72 * time.Hour, 3, false},
		{"early weekly needs weekday", SeasonalWeeklyEarly, 6 * 24 * time.Hour, 0, false},
		{"early weekly nine days", SeasonalWeeklyEarly, 9 * 24 * time.Hour, 7, true},
		{"early weekly fifteen days", SeasonalWeeklyEarly, 15 * 24 * time.Hour, 11, true},
		{"early weekly graduation", SeasonalWeeklyEarly, 21 * 24 * time.Hour, 3, false},
		{"strict weekly cold", SeasonalWeekly, 15 * 24 * time.Hour, 0, false},
		{"strict weekly twenty one days", SeasonalWeekly, 21 * 24 * time.Hour, 3, false},
		{"strict weekly six weeks", SeasonalWeekly, 42 * 24 * time.Hour, 6, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			model := cadenceModel(t, tc.cadence)
			observed := start.Add(tc.elapsed)
			points := make([]Feature, 0, int(tc.elapsed/(15*time.Minute))+1)
			for at := start; !at.After(observed); at = at.Add(15 * time.Minute) {
				// The stable within-hour range is normal for a clock-hour
				// model. The hourly profile specifically matches one minute.
				points = append(points, cadencePoint(at, 100+float64(at.Minute()/15)))
			}
			normal := scoreCadenceReplay(t, model, points)
			points[len(points)-1].Value += 40
			planted := scoreCadenceReplay(t, model, points)
			if tc.periods == 0 {
				if normal.State != SeasonalWarming || planted.State != SeasonalWarming || normal.Evidence != nil {
					t.Fatalf("scored an ineligible checkpoint: normal=%+v planted=%+v", normal, planted)
				}
				return
			}
			if normal.State != SeasonalNormal || planted.State != SeasonalUp || planted.Evidence == nil ||
				planted.ComparableDays != tc.periods || planted.Evidence.Provisional != tc.provisional || len(planted.Citations) != 3 {
				t.Fatalf("want %d periods and provisional=%t: normal=%+v planted=%+v", tc.periods, tc.provisional, normal, planted)
			}
			if tc.cadence == SeasonalHourly && (planted.Evidence.Minute == nil || *planted.Evidence.Minute != 0 || planted.Evidence.Median != 100) {
				t.Fatalf("hourly training mixed minutes: %+v", planted.Evidence)
			}
		})
	}
}

func TestProvisionalWeeklyExactIncludesObservedWeekdayAndRefusesSibling(t *testing.T) {
	const anchor = "36893488147419103226"
	const low = "36893488147419103100"
	const high = "36893488147419103228"
	model := cadenceModel(t, SeasonalWeeklyEarly)
	at := time.Date(2026, 11, 18, 10, 59, 59, 0, time.UTC)
	now := ExactSeasonalFeature{Feature: cadencePoint(at, 0), Decimal: anchor}
	past := []ExactSeasonalFeature{
		{Feature: cadencePoint(at.AddDate(0, 0, -7), 0), Decimal: anchor},
		{Feature: cadencePoint(at.AddDate(0, 0, -6), 0), Decimal: low},
		{Feature: cadencePoint(at.AddDate(0, 0, -5), 0), Decimal: low},
		{Feature: cadencePoint(at.AddDate(0, 0, -2), 0), Decimal: low},
	}
	check := func(current ExactSeasonalFeature, want SeasonalState) {
		t.Helper()
		got, err := model.CompareDecimalSeries(t.Context(), "owned", current, past, 3, 1<<20)
		if err != nil || got.State != want || got.Band == nil || got.Calendar == nil || !got.Calendar.Provisional ||
			got.Band.Upper != "36893488147419103227" || got.Band.Current != current.Decimal {
			t.Fatalf("exact provisional weekday lost its original ceiling: %+v (%v)", got, err)
		}
	}
	check(now, SeasonalNormal)
	now.Decimal = high
	check(now, SeasonalUp)
	past[1].TenantID = "sibling"
	if got, err := model.CompareDecimalSeries(t.Context(), "owned", now, past, 3, 1<<20); !errors.Is(err, ErrCrossTenantFeature) || got.Band != nil {
		t.Fatal("foreign cadence sample reached training", err)
	}
}

func TestHourlyFoldCountsOnceAndSeasonalPlansExcludeHolidays(t *testing.T) {
	zone := "America/New_York"
	model, err := NewWeeklySeasonalModel(WeeklySeasonalConfig{Timezone: zone, Cadence: SeasonalHourly, MinimumDays: 3,
		MinimumDeviation: 1, Holidays: []string{"2026-10-31"}})
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Date(2026, 11, 1, 8, 20, 0, 0, time.UTC)
	inputs := []Feature{
		cadencePoint(time.Date(2026, 10, 31, 23, 20, 0, 0, time.UTC), 1000),
		cadencePoint(time.Date(2026, 11, 1, 5, 20, 0, 0, time.UTC), 90),
		cadencePoint(time.Date(2026, 11, 1, 6, 20, 0, 0, time.UTC), 110),
		cadencePoint(time.Date(2026, 11, 1, 7, 20, 0, 0, time.UTC), 100),
		cadencePoint(observed, 100),
	}
	result := scoreCadenceReplay(t, model, inputs)
	if result.State != SeasonalWarming || result.ComparableDays != 2 {
		t.Fatalf("fold or excluded local date inflated the comparison: %+v", result)
	}
	planned := model.ComparableWindows(observed)
	loc := observed.In(model.location)
	for _, w := range planned {
		start := w.Start.In(model.location)
		if start.Format(time.DateOnly) == "2026-10-31" || start.Minute() != loc.Minute() || w.End.Sub(w.Start) > time.Minute {
			t.Fatal("planner returned time outside its series cadence or holiday", w)
		}
	}
}

func cadencePoint(at time.Time, value float64) Feature {
	return Feature{TenantID: "owned", Plane: "active", Source: "tsdb", Subject: "owned-test", Metric: "duration",
		TS: at, Value: value, Citation: "metric:" + at.Format(time.RFC3339Nano)}
}

func cadenceModel(t *testing.T, cadence SeasonalCadence) WeeklySeasonalModel {
	t.Helper()
	model, err := NewWeeklySeasonalModel(WeeklySeasonalConfig{Timezone: "UTC", Cadence: cadence, MinimumDays: 3, MinimumDeviation: 1})
	if err != nil {
		t.Fatal(err)
	}
	return model
}

func scoreCadenceReplay(t *testing.T, model WeeklySeasonalModel, points []Feature) SeasonalComparison {
	t.Helper()
	got, err := model.Compare(t.Context(), points, Query{TenantID: "owned", Sensitivity: 3})
	if err != nil || len(got) != 1 {
		t.Fatalf("expected one retained series: %+v (%v)", got, err)
	}
	return got[0]
}
