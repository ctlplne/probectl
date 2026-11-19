// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sort"
	"time"
	_ "time/tzdata" // keep IANA calendars available in air-gapped binaries
)

type WeeklySeasonalConfig struct {
	Cadence          SeasonalCadence
	Timezone         string
	Holidays         []string // local YYYY-MM-DD
	MinimumDays      int
	MinimumDeviation float64
}

type SeasonalEvidence struct {
	Cadence      SeasonalCadence `json:"cadence,omitempty"`
	Periods      int             `json:"training_periods,omitempty"`
	Minute       *int            `json:"minute,omitempty"`
	Provisional  bool            `json:"provisional,omitempty"`
	Timezone     string          `json:"timezone"`
	Weekday      time.Weekday    `json:"weekday"`
	Hour         int             `json:"hour"`
	TrainingDays []string        `json:"training_days"`
	Median       float64         `json:"median"`
	RobustSpread float64         `json:"robust_spread"`
	Lower        float64         `json:"lower"`
	Upper        float64         `json:"upper"`
}

type WeeklySeasonalModel struct {
	cadence          SeasonalCadence
	location         *time.Location
	holidays         map[string]bool
	minimumDays      int
	minimumDeviation float64
}

const WeeklyTrainingWeeks = 6

// SeasonalWindow covers [Start, End) in UTC. A repeated local hour can
// include more than one continuous offset interval.
type SeasonalWindow struct {
	Start time.Time
	End   time.Time
}

// ComparableWindows identifies the retained-hour reads needed before a
// comparison. The timezone map handles repeated and skipped hours directly.
func (m WeeklySeasonalModel) ComparableWindows(observed time.Time) []SeasonalWindow {
	if m.location == nil || observed.IsZero() {
		return nil
	}
	local := observed.In(m.location)
	if m.holidays[local.Format(time.DateOnly)] {
		return nil
	}
	return m.profileWindows(local)
}

func (m WeeklySeasonalModel) appendLocalHour(windows []SeasonalWindow, wall time.Time) []SeasonalWindow {
	// Search across all the possible UTC offsets around that civil hour. Each
	// constant-offset interval contributes only times inside the named hour.
	remainingUntil := wall.Add(26 * time.Hour)
	for cursor := wall.Add(-26 * time.Hour); cursor.Before(remainingUntil); {
		local := cursor.In(m.location)
		_, offset := local.Zone()
		_, transition := local.ZoneBounds()
		end := remainingUntil
		if !transition.IsZero() && transition.Before(end) {
			end = transition.UTC()
		}
		hour := wall.Add(-time.Duration(offset) * time.Second)
		start := laterSeasonalTime(cursor, hour)
		until := earlierSeasonalTime(end, hour.Add(time.Hour))
		if start.Before(until) {
			windows = append(windows, SeasonalWindow{Start: start, End: until})
		}
		cursor = end
	}
	return windows
}

func laterSeasonalTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func earlierSeasonalTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

type SeasonalState string

const (
	SeasonalUnavailable SeasonalState = "unavailable"
	SeasonalExcluded    SeasonalState = "holiday"
	SeasonalWarming     SeasonalState = "warming"
	SeasonalNormal      SeasonalState = "within_band"
	SeasonalUp          SeasonalState = "up"
	SeasonalDown        SeasonalState = "down"
)

// SeasonalComparison preserves a holiday or an incomplete history as an
// unevaluated observation. Consumers must not resolve a live episode from it.
type SeasonalComparison struct {
	State           SeasonalState
	Observed        Feature
	ComparableDays  int
	RequiredPeriods int
	Evidence        *SeasonalEvidence
	Exact           *SeasonalDecimalBand
	TrainingWindow  TrainingWindow
	Citations       []Citation
	Score           float64
}

func NewWeeklySeasonalModel(config WeeklySeasonalConfig) (WeeklySeasonalModel, error) {
	var none WeeklySeasonalModel
	if config.Timezone == "" || config.Timezone == "Local" || config.MinimumDays < 3 ||
		config.MinimumDeviation <= 0 || !finiteSeasonalValue(config.MinimumDeviation) {
		return none, fmt.Errorf("anomaly: seasonal model needs an explicit timezone, at least three training days and a positive deviation floor")
	}
	if !config.Cadence.Valid() {
		return none, fmt.Errorf("anomaly: invalid seasonal cadence %q", config.Cadence)
	}
	location, err := time.LoadLocation(config.Timezone)
	if err != nil {
		return none, fmt.Errorf("anomaly: invalid seasonal timezone: %w", err)
	}
	holidays := make(map[string]bool, len(config.Holidays))
	for _, date := range config.Holidays {
		day, err := time.Parse(time.DateOnly, date)
		if err != nil || day.Format(time.DateOnly) != date {
			return none, fmt.Errorf("anomaly: seasonal holidays must be calendar dates")
		}
		holidays[date] = true
	}
	return WeeklySeasonalModel{
		cadence: config.Cadence, location: location, holidays: holidays, minimumDays: config.MinimumDays, minimumDeviation: config.MinimumDeviation,
	}, nil
}

func (m WeeklySeasonalModel) Name() string {
	if m.cadence == "" || m.cadence == SeasonalWeekly {
		return "local-weekly-seasonal-v1"
	}
	return "local-" + string(m.cadence) + "-seasonal-v1"
}

func (m WeeklySeasonalModel) Evaluate(ctx context.Context, features []Feature, query Query) ([]Finding, error) {
	comparisons, err := m.Compare(ctx, features, query)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for _, result := range comparisons {
		if result.State != SeasonalUp && result.State != SeasonalDown {
			continue
		}
		current := result.Observed
		findings = append(findings, Finding{
			TenantID: current.TenantID, Plane: current.Plane, Source: current.Source, Subject: current.Subject,
			Metric: current.Metric, TS: current.TS, Current: current.Value, Baseline: result.Evidence.Median,
			Score: result.Score, Direction: string(result.State), Model: m.Name(),
			TrainingWindow: result.TrainingWindow, Citations: result.Citations, Seasonal: result.Evidence,
			Features: map[string]float64{current.Plane + "." + current.Metric: current.Value},
		})
	}
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Score > findings[j].Score })
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

// Compare scores only the latest point in each full tenant-local series key.
// The configured minimum allows an explicitly chosen lower observation floor.
func (m WeeklySeasonalModel) Compare(ctx context.Context, features []Feature, query Query) ([]SeasonalComparison, error) {
	if query.TenantID == "" {
		return nil, ErrNoTenant
	}
	if m.location == nil {
		return nil, fmt.Errorf("anomaly: seasonal calendar is unavailable")
	}
	if !finiteSeasonalValue(query.Sensitivity) || !finiteSeasonalValue(query.MinValue) {
		return nil, fmt.Errorf("anomaly: seasonal sensitivity and minimum must be finite")
	}
	if query.Sensitivity <= 0 {
		query.Sensitivity = 3
	}
	for _, feature := range features {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if feature.TenantID != query.TenantID {
			return nil, ErrCrossTenantFeature
		}
	}
	var comparisons []SeasonalComparison
	for _, points := range groupSeries(features) {
		result, err := m.compareSeries(ctx, points, query)
		if err != nil {
			return nil, err
		}
		comparisons = append(comparisons, result)
	}
	sort.Slice(comparisons, func(i, j int) bool {
		left, right := comparisons[i].Observed, comparisons[j].Observed
		if left.Subject != right.Subject {
			return left.Subject < right.Subject
		}
		if left.Metric != right.Metric {
			return left.Metric < right.Metric
		}
		if left.Plane != right.Plane {
			return left.Plane < right.Plane
		}
		return left.Source < right.Source
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return comparisons, nil
}

func (m WeeklySeasonalModel) compareSeries(ctx context.Context, points []Feature, query Query) (SeasonalComparison, error) {
	sort.Slice(points, func(i, j int) bool { return points[i].TS.Before(points[j].TS) })
	current := points[len(points)-1]
	result := SeasonalComparison{State: SeasonalUnavailable, Observed: current, RequiredPeriods: m.minimumPeriods()}
	if !finiteSeasonalValue(current.Value) || (query.MinValue != 0 && current.Value < query.MinValue) ||
		(len(points) > 1 && current.TS.Equal(points[len(points)-2].TS)) {
		// Even the exact current value is ambiguous in this state.
		result.Observed.Value, result.Observed.Citation, result.Observed.Attrs = 0, "", nil
		return result, nil
	}
	slot := current.TS.In(m.location)
	currentDate := slot.Format(time.DateOnly)
	if m.holidays[currentDate] {
		result.State = SeasonalExcluded
		return result, nil
	}
	history, days, err := m.comparableTraining(ctx, points[:len(points)-1], slot)
	if err != nil {
		return SeasonalComparison{}, err
	}
	ready, anchors := selectSeasonalPeriods(m, slot, days)
	result.ComparableDays = len(days)
	if !ready {
		result.State = SeasonalWarming
		return result, nil
	}
	history = slices.DeleteFunc(history, func(point Feature) bool { return days[m.trainingSlot(point.TS, slot)] == nil })
	return m.compareSeasonalBand(result, query, slot, history, days, anchors), nil
}

func (m WeeklySeasonalModel) compareSeasonalBand(result SeasonalComparison, query Query, slot time.Time, history []Feature, periods map[string][]float64, anchors map[string]bool) SeasonalComparison {
	baseline, spread, slots := seasonalCenter(periods)
	// A measured change floor handles stable series. A provisional weekly
	// band also includes every available actual same-weekday center.
	delta := math.Max(spread*query.Sensitivity, m.minimumDeviation)
	lower, upper := baseline-delta, baseline+delta
	for anchor := range anchors {
		center := seasonalMedian(periods[anchor])
		lower = min(lower, center-m.minimumDeviation)
		upper = max(upper, center+m.minimumDeviation)
	}
	if !finiteSeasonalValue(lower) || !finiteSeasonalValue(upper) {
		return result
	}
	current := result.Observed
	change := current.Value - baseline
	radius := delta
	if len(anchors) > 0 {
		radius = max(delta, baseline-lower, upper-baseline)
	}
	score := math.Abs(change) / (radius / query.Sensitivity)
	if !finiteSeasonalValue(score) {
		return result
	}
	result.State = SeasonalNormal
	if current.Value < lower {
		result.State = SeasonalDown
	} else if current.Value > upper {
		result.State = SeasonalUp
	}
	result.Score = score
	result.TrainingWindow = TrainingWindow{Start: history[0].TS, End: history[len(history)-1].TS, Samples: len(history)}
	result.Citations = append(currentCitation(current), trainingCitations(history)...)
	evidence := m.profileEvidence(slot, slots, len(anchors) != 0)
	evidence.Median, evidence.RobustSpread, evidence.Lower, evidence.Upper = baseline, spread, lower, upper
	result.Evidence = &evidence
	return result
}

func (m WeeklySeasonalModel) comparableTraining(ctx context.Context, before []Feature, slot time.Time) ([]Feature, map[string][]float64, error) {
	periods := map[string][]float64{}
	var history []Feature
	for i, point := range before {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		// Multiple records at the same instant make that instant ambiguous.
		if (i > 0 && point.TS.Equal(before[i-1].TS)) || (i+1 < len(before) && point.TS.Equal(before[i+1].TS)) {
			continue
		}
		period := m.trainingSlot(point.TS, slot)
		if period == "" || !finiteSeasonalValue(point.Value) {
			continue
		}
		periods[period] = append(periods[period], point.Value)
		history = append(history, point)
	}
	return history, periods, nil
}

func seasonalCenter(periods map[string][]float64) (center, spread float64, slots []string) {
	medians := make([]float64, 0, len(periods))
	within := make([]float64, 0, len(periods))
	slots = make([]string, 0, len(periods))
	for slot, values := range periods {
		median := seasonalMedian(values)
		medians = append(medians, median)
		within = append(within, seasonalAbsoluteDeviation(values, median))
		slots = append(slots, slot)
	}
	sort.Strings(slots)
	center = seasonalMedian(medians)
	// Each period still has one vote. Its typical internal variation
	// prevents repeatedly observed values within the same clock hour from
	// triggering merely because the per-hour medians happen to be equal.
	spread = 1.4826 * max(seasonalAbsoluteDeviation(medians, center), seasonalMedian(within))
	return center, spread, slots
}

func seasonalAbsoluteDeviation(values []float64, center float64) float64 {
	deviations := make([]float64, len(values))
	for i, value := range values {
		deviations[i] = math.Abs(value - center)
	}
	return seasonalMedian(deviations)
}

func seasonalMedian(values []float64) float64 {
	sort.Float64s(values)
	middle := len(values) / 2
	if len(values)%2 != 0 {
		return values[middle]
	}
	return values[middle-1]/2 + values[middle]/2
}

func finiteSeasonalValue(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}
