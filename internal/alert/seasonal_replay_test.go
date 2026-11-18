// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
)

func TestWeeklySeasonalReplayAgainstCurrentAlertRule(t *testing.T) {
	const day = 24 * time.Hour
	const sensitivity = 3
	const tenant = "seasonal-replay"
	start := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	model, err := anomaly.NewWeeklySeasonalModel(anomaly.WeeklySeasonalConfig{
		Timezone: "UTC", MinimumDays: 3, MinimumDeviation: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	rolling := newBaseline(20) // same window and sensitivity as the current form
	planted := map[time.Time]float64{
		start.Add(35*day + day + 10*time.Hour):   145, // workday spike
		start.Add(42*day + 2*day + 11*time.Hour): 18,  // workday drop
		start.Add(49*day + 5*day + 2*time.Hour):  60,  // weekend spike
	}
	type count struct{ detected, falseAlarms int }
	var current, seasonal count
	var replay []anomaly.Feature
	var normal int
	for at := start; at.Before(start.Add(56 * day)); at = at.Add(time.Hour) {
		value, injected := planted[at]
		if !injected {
			value = replaySeasonalReading(at)
		}
		old := rolling.evaluate(value, sensitivity)
		replay = append(replay, anomaly.Feature{TenantID: tenant, Source: "simulation", Plane: "active", Subject: "branch", Metric: "rate",
			TS: at, Value: value, Citation: "replay:" + at.Format(time.RFC3339)})
		if at.Before(start.Add(35 * day)) {
			continue
		}
		findings, err := model.Evaluate(t.Context(), replay, anomaly.Query{TenantID: tenant, Sensitivity: sensitivity})
		if err != nil {
			t.Fatal(err)
		}
		if injected {
			if old.anomalous {
				current.detected++
			}
			if len(findings) == 1 && findings[0].TS.Equal(at) && len(findings[0].Citations) >= 2 {
				seasonal.detected++
			}
			continue
		}
		normal++
		if old.anomalous {
			current.falseAlarms++
		}
		seasonal.falseAlarms += len(findings)
	}
	t.Logf("same hourly replay, rolling detection %d/%d, false alarms %d/%d, weekly detection %d/%d, false alarms %d/%d",
		current.detected, len(planted), current.falseAlarms, normal, seasonal.detected, len(planted), seasonal.falseAlarms, normal)
	if seasonal.detected != len(planted) || seasonal.falseAlarms != 0 || current.falseAlarms == 0 {
		t.Fatal("expected the weekly model to distinguish the planted changes from normal workdays")
	}
}

func replaySeasonalReading(at time.Time) float64 {
	if at.Weekday() == time.Saturday || at.Weekday() == time.Sunday {
		return 24
	}
	if at.Hour() >= 10 && at.Hour() < 15 {
		return 90
	}
	return 20
}

func TestWeeklySeasonalWarmupReportsComparableCoverage(t *testing.T) {
	const day = 24 * time.Hour
	const tenant = "seasonal-cold-start"
	start := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	model, err := anomaly.NewWeeklySeasonalModel(anomaly.WeeklySeasonalConfig{Timezone: "UTC", MinimumDays: 3, MinimumDeviation: 8})
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		age  time.Duration
		days int
	}{
		{5 * time.Hour, 0}, {2*day + 12*time.Hour, 0}, {9 * day, 1},
		{15 * day, 2}, {21 * day, 3}, {42 * day, 6},
	}
	for _, check := range checks {
		t.Run(check.age.String(), func(t *testing.T) {
			rolling := newBaseline(20)
			end := start.Add(check.age)
			features := make([]anomaly.Feature, 0, int(check.age/(15*time.Minute))+1)
			var old baselineEvaluation
			for at := start; !at.After(end); at = at.Add(15 * time.Minute) {
				value := replaySeasonalReading(at)
				if at.Equal(end) {
					value += 36
				}
				old = rolling.evaluate(value, 3)
				features = append(features, anomaly.Feature{TenantID: tenant, Plane: "active", Source: "simulation", Subject: "site", Metric: "rate",
					TS: at, Value: value, Citation: "history:" + at.Format(time.RFC3339)})
			}
			result, err := model.Compare(t.Context(), features, anomaly.Query{TenantID: tenant, Sensitivity: 3})
			if err != nil || len(result) != 1 || old.warming {
				t.Fatal("could not compare the same cold-start population", err)
			}
			state := anomaly.SeasonalWarming
			if check.days >= 3 {
				state = anomaly.SeasonalUp
			}
			if result[0].State != state || result[0].ComparableDays != check.days {
				t.Fatal("the reported readiness disagrees with retained weekday/hour coverage", result[0].State, result[0].ComparableDays)
			}
			t.Logf("15-minute replay after %s uses %d matching dates, rolling detected=%t weekly state=%s", check.age, check.days, old.anomalous, result[0].State)
		})
	}
}
