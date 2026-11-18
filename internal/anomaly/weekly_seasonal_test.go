// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"
)

func TestWeeklySeasonalSelectsOwnedLocalTrainingDays(t *testing.T) {
	zone, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	const tenant = "owned-seasonal"
	const folded = "2026-11-01"
	current := time.Date(2026, 11, 22, 1, 20, 0, 0, zone)
	model, err := NewWeeklySeasonalModel(WeeklySeasonalConfig{
		Timezone: zone.String(), Holidays: []string{"2026-10-25"}, MinimumDays: 3, MinimumDeviation: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	point := func(at time.Time, n float64) Feature {
		return Feature{TenantID: tenant, Plane: "flow", Source: "clickhouse", Subject: "owned-wan", Metric: "rate", TS: at.UTC(), Value: n, Citation: "fixture:" + at.Format(time.RFC3339)}
	}
	var points []Feature
	for _, offset := range []int{-42, -35, -14, -7} {
		at := current.AddDate(0, 0, offset)
		points = append(points, point(at, 100+float64(offset%3)))
		// Same hour on a different weekday cannot influence the range.
		points = append(points, point(at.AddDate(0, 0, 1), 2000))
	}
	// The two occurrences of 01:30 on the same local Sunday contribute one
	// training date. A repeated record for the same instant contributes none.
	first := time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC)
	second := first.Add(time.Hour)
	points = append(points, point(first, 98), point(second, 102), point(second.Add(time.Minute), 500), point(second.Add(time.Minute), 500))
	points = append(points, point(current.AddDate(0, 0, -28), 500), point(current.AddDate(0, 0, -21).Add(3*time.Hour), 600))
	for _, visit := range []struct {
		sample float64
		want   string
	}{{144, "up"}, {52, "down"}, {102, ""}} {
		features := append(append([]Feature(nil), points...), point(current, visit.sample))
		findings, err := model.Evaluate(t.Context(), features, Query{TenantID: tenant, Sensitivity: 3})
		if err != nil || (len(findings) == 0) != (visit.want == "") {
			t.Fatalf("wrong seasonal result for %g: %v (%v)", visit.sample, findings, err)
		}
		if visit.want != "" {
			f := findings[0]
			evidence := f.Seasonal
			if f.Direction != visit.want || evidence == nil || evidence.Hour != 1 || evidence.Weekday != time.Sunday ||
				len(evidence.TrainingDays) != 5 || evidence.TrainingDays[2] != folded || f.TrainingWindow.Samples != 6 ||
				f.Current != visit.sample || f.Baseline < 97 || f.Baseline > 100 || len(f.Citations) != 3 {
				t.Fatalf("wrong original seasonal evidence: %+v %+v", f, evidence)
			}
		}
		foreign := point(current.Add(-time.Minute), 290)
		foreign.TenantID = "sibling"
		if out, err := model.Evaluate(t.Context(), append(features, foreign), Query{TenantID: tenant}); !errors.Is(err, ErrCrossTenantFeature) || len(out) != 0 {
			t.Fatalf("sibling input did not fail closed: %v (%v)", out, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if out, err := model.Evaluate(ctx, points, Query{TenantID: tenant}); !errors.Is(err, context.Canceled) || len(out) != 0 {
		t.Fatalf("cancelled seasonal read published a prefix: %v (%v)", out, err)
	}
}

func TestWeeklySeasonalRequiresUsableComparableDays(t *testing.T) {
	const tenant = "owned"
	current := time.Date(2026, 1, 27, 10, 30, 0, 0, time.UTC)
	model, err := NewWeeklySeasonalModel(WeeklySeasonalConfig{
		Timezone: "UTC", Holidays: []string{"2026-01-20", "2026-02-03"}, MinimumDays: 3, MinimumDeviation: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	feature := func(at time.Time, value float64) Feature {
		return Feature{TenantID: tenant, Plane: "active", Source: "local", Subject: "test", Metric: "value", TS: at, Value: value}
	}
	history := []Feature{
		feature(current.AddDate(0, 0, -28), -10), feature(current.AddDate(0, 0, -21), -10), feature(current.AddDate(0, 0, -14), -10),
		feature(current.AddDate(0, 0, -7), 200),
	}
	for _, tt := range []struct {
		name   string
		points []Feature
		want   SeasonalState
	}{
		{"signed values", append(history, feature(current, -30)), SeasonalDown},
		{"within inclusive bounds", append(history, feature(current, -15)), SeasonalNormal},
		{"insufficient comparable days", append(history[1:], feature(current, -30)), SeasonalWarming},
		{"holiday current", append(history, feature(current.AddDate(0, 0, 7), -30)), SeasonalExcluded},
		{"non-finite current", append(history, feature(current, math.Inf(1))), SeasonalUnavailable},
		{"duplicate current", append(history, feature(current, -30), feature(current, -29)), SeasonalUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			comparisons, err := model.Compare(t.Context(), tt.points, Query{TenantID: tenant})
			if err != nil || len(comparisons) != 1 || comparisons[0].State != tt.want {
				t.Fatalf("want %s, got %+v (%v)", tt.want, comparisons, err)
			}
		})
	}
}

func TestWeeklySeasonalHistoryWindowsFollowActualDaylightSavings(t *testing.T) {
	model, err := NewWeeklySeasonalModel(WeeklySeasonalConfig{
		Timezone: "America/New_York", MinimumDays: 3, MinimumDeviation: 2, Holidays: []string{"2026-10-25"},
	})
	if err != nil {
		t.Fatal(err)
	}
	stamp := func(raw string) time.Time {
		at, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			t.Fatal(err)
		}
		return at
	}
	fold := model.ComparableWindows(stamp("2026-11-22T06:20:00Z"))
	if len(fold) != 6 || !fold[2].Start.Equal(stamp("2026-11-01T05:00:00Z")) ||
		!fold[2].End.Equal(stamp("2026-11-01T06:00:00Z")) || !fold[3].Start.Equal(fold[2].End) ||
		!fold[3].End.Equal(stamp("2026-11-01T07:00:00Z")) {
		t.Fatalf("folded hour overlap or holiday exclusion changed: %+v", fold)
	}
	skip := model.ComparableWindows(stamp("2026-03-15T06:20:00Z"))
	if len(skip) != 5 || !skip[4].Start.Equal(stamp("2026-03-01T07:00:00Z")) {
		t.Fatalf("nonexistent spring hour produced history: %+v", skip)
	}
}
