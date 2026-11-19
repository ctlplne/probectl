// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"maps"
	"slices"
	"strings"
	"time"
)

// SeasonalCadence determines what counts as a comparable calendar period.
type SeasonalCadence string

const (
	SeasonalWeekly      SeasonalCadence = "weekly"
	SeasonalHourly      SeasonalCadence = "hourly"
	SeasonalDaily       SeasonalCadence = "daily"
	SeasonalWeeklyEarly SeasonalCadence = "weekly_early"

	seasonalTrainingDays = 7 * WeeklyTrainingWeeks
	seasonalEarlyDays    = 15
	civilHourLayout      = "2006-01-02T15"
)

func (s SeasonalCadence) Valid() bool {
	switch s {
	case "", SeasonalWeekly, SeasonalHourly, SeasonalDaily, SeasonalWeeklyEarly:
		return true
	default:
		return false
	}
}

func (m WeeklySeasonalModel) Cadence() SeasonalCadence { return m.cadence }

// ComparableSample applies the same calendar before the source adapter holds
// a bulk raw sample in the scoring population.
func (m WeeklySeasonalModel) ComparableSample(sample, observed time.Time) bool {
	return m.location != nil && !observed.IsZero() && !m.holidays[observed.In(m.location).Format(time.DateOnly)] &&
		m.trainingSlot(sample, observed.In(m.location)) != ""
}

// HourlyReadStart includes every possible matching minute in the retained
// civil span. Scoring disregards input outside the exact calendar range.
func (m WeeklySeasonalModel) HourlyReadStart(oldest time.Time) time.Time {
	if m.cadence != SeasonalHourly || oldest.IsZero() {
		return time.Time{}
	}
	wall := seasonalWall(oldest.In(m.location)).AddDate(0, 0, -seasonalTrainingDays)
	return wall.Add(-26 * time.Hour)
}

func (m WeeklySeasonalModel) minimumPeriods() int {
	if m.cadence == SeasonalDaily || m.cadence == SeasonalWeeklyEarly {
		return 2
	}
	return m.minimumDays
}

func seasonalWall(at time.Time) time.Time {
	return time.Date(at.Year(), at.Month(), at.Day(), at.Hour(), 0, 0, 0, time.UTC)
}

func (m WeeklySeasonalModel) profileWindows(local time.Time) []SeasonalWindow {
	wall := seasonalWall(local)
	if m.cadence == SeasonalHourly {
		return m.hourlyWindows(wall, local.Minute(), seasonalTrainingDays*24)
	}

	step := 1
	if m.cadence == "" || m.cadence == SeasonalWeekly {
		step = 7
	}
	windows := make([]SeasonalWindow, 0, seasonalTrainingDays/step)
	for days := seasonalTrainingDays; days > 0; days -= step {
		prior := wall.AddDate(0, 0, -days)
		if m.profileDate(prior, wall) {
			windows = m.appendLocalHour(windows, prior)
		}
	}
	return windows
}

func (m WeeklySeasonalModel) hourlyWindows(wall time.Time, minute, hours int) []SeasonalWindow {
	minuteOffset := time.Duration(minute) * time.Minute
	var windows []SeasonalWindow
	for i := hours; i > 0; i-- {
		prior := wall.Add(-time.Duration(i) * time.Hour)
		if m.holidays[prior.Format(time.DateOnly)] {
			continue
		}
		for _, hour := range m.appendLocalHour(nil, prior) {
			_, offset := hour.Start.In(m.location).Zone()
			start := prior.Add(minuteOffset - time.Duration(offset)*time.Second)
			from, to := laterSeasonalTime(start, hour.Start), earlierSeasonalTime(start.Add(time.Minute), hour.End)
			if from.Before(to) {
				windows = append(windows, SeasonalWindow{Start: from, End: to})
			}
		}
	}
	return windows
}

func (m WeeklySeasonalModel) profileDate(prior, observed time.Time) bool {
	if m.holidays[prior.Format(time.DateOnly)] {
		return false
	}
	if m.cadence == SeasonalDaily || prior.Weekday() == observed.Weekday() {
		return true
	}
	return m.cadence == SeasonalWeeklyEarly && !prior.Before(observed.AddDate(0, 0, -seasonalEarlyDays)) &&
		seasonalWeekend(prior.Weekday()) == seasonalWeekend(observed.Weekday())
}

func seasonalWeekend(day time.Weekday) bool { return day == time.Saturday || day == time.Sunday }

// trainingSlot matches the same civil clock population as profileWindows. The
// two occurrences of a folded hour share one vote.
func (m WeeklySeasonalModel) trainingSlot(at, observed time.Time) string {
	if !at.Before(observed) {
		return ""
	}
	clock, wall := at.In(m.location), seasonalWall(observed)
	prior := seasonalWall(clock)
	if !prior.Before(wall) || prior.Before(wall.AddDate(0, 0, -seasonalTrainingDays)) {
		return ""
	}
	if m.cadence == SeasonalHourly {
		if clock.Minute() == observed.Minute() && !m.holidays[clock.Format(time.DateOnly)] {
			return prior.Format(civilHourLayout)
		}
		return ""
	}
	if prior.Hour() == wall.Hour() && m.profileDate(prior, wall) {
		return prior.Format(time.DateOnly)
	}
	return ""
}

// selectSeasonalPeriods promotes a weekly profile once it has enough actual
// matches. The provisional band still requires a same-weekday observation.
func selectSeasonalPeriods[T any](m WeeklySeasonalModel, observed time.Time, slots map[string][]T) (ready bool, anchors map[string]bool) {
	if len(slots) < m.minimumPeriods() {
		return false, nil
	}
	if m.cadence != SeasonalWeeklyEarly {
		return true, nil
	}
	anchors = make(map[string]bool)
	for slot := range slots {
		date, err := time.Parse(time.DateOnly, slot)
		if err == nil && date.Weekday() == observed.Weekday() {
			anchors[slot] = true
		}
	}
	if len(anchors) >= m.minimumDays {
		maps.DeleteFunc(slots, func(slot string, _ []T) bool { return !anchors[slot] })
		return true, nil
	}
	return len(anchors) > 0, anchors
}

func seasonalTrainingDates(slots []string) []string {
	dates := make([]string, 0, len(slots))
	for _, slot := range slots {
		date, _, _ := strings.Cut(slot, "T")
		dates = append(dates, date)
	}
	return slices.Compact(dates)
}

func (m WeeklySeasonalModel) profileEvidence(slot time.Time, periods []string, provisional bool) SeasonalEvidence {
	evidence := SeasonalEvidence{Timezone: m.location.String(), Weekday: slot.Weekday(), Hour: slot.Hour(),
		TrainingDays: seasonalTrainingDates(periods), Cadence: m.cadence, Provisional: provisional || (m.cadence == SeasonalDaily && len(periods) == 2)}
	if m.cadence != "" && m.cadence != SeasonalWeekly {
		evidence.Periods = len(periods)
	}
	if m.cadence == SeasonalHourly {
		minute := slot.Minute()
		evidence.Minute = &minute
	}
	return evidence
}
