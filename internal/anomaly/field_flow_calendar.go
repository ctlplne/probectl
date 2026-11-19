// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import "time"

type FlowFieldComparisonCadence string

const (
	FlowFieldPreviousPeriod FlowFieldComparisonCadence = "previous_period"
	FlowFieldPreviousWeek   FlowFieldComparisonCadence = "previous_week"
	FlowFieldCompleteWeek   FlowFieldComparisonCadence = "complete_week"
	FlowFieldHourlyWeek     FlowFieldComparisonCadence = "hourly_1w"
	FlowFieldHourlyMonth    FlowFieldComparisonCadence = "hourly_4w"
)

type FlowFieldComparisonClocks struct {
	Before, After TrainingWindow
	History       TrainingWindow
}

// FlowFieldHistoryHours counts all prior completed hours in a membership preset.
func FlowFieldHistoryHours(cadence FlowFieldComparisonCadence) int {
	switch cadence {
	case FlowFieldHourlyWeek:
		return 7 * 24
	case FlowFieldHourlyMonth:
		return 28 * 24
	default:
		return 0
	}
}

// Ends returns the full ordered set of completed input clocks for one comparison.
func (c FlowFieldComparisonClocks) Ends() []time.Time {
	if c.History.Samples == 0 {
		return []time.Time{c.Before.End, c.After.End}
	}
	ends := make([]time.Time, c.History.Samples+1)
	for i := range ends {
		ends[i] = c.History.Start.Add(time.Duration(i+1) * time.Hour)
	}
	return ends
}

// FlowFieldCompletedWindows aligns two equal-length fixed source windows to
// the same UTC clock. Complete-week views use the preceding two full weeks,
// ending at the most recent complete UTC day.
func FlowFieldCompletedWindows(at time.Time, cadence FlowFieldComparisonCadence, periodSeconds int) (FlowFieldComparisonClocks, error) {
	var out FlowFieldComparisonClocks
	if at.IsZero() {
		return out, ErrFlowFieldCoverage
	}
	at = at.UTC()
	if cadence == FlowFieldCompleteWeek {
		if periodSeconds != 0 {
			return out, ErrFlowFieldCoverage
		}
		end := time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
		out.After = TrainingWindow{Start: end.AddDate(0, 0, -7), End: end}
		out.Before = TrainingWindow{Start: end.AddDate(0, 0, -14), End: out.After.Start}
		return out, nil
	}
	if hours := FlowFieldHistoryHours(cadence); hours != 0 {
		if periodSeconds != 3600 {
			return out, ErrFlowFieldCoverage
		}
		end := at.Truncate(time.Hour)
		out.After = TrainingWindow{Start: end.Add(-time.Hour), End: end}
		out.Before = TrainingWindow{Start: end.Add(-2 * time.Hour), End: out.After.Start}
		out.History = TrainingWindow{Start: out.After.Start.Add(-time.Duration(hours) * time.Hour), End: out.After.Start, Samples: hours}
		return out, nil
	}
	switch periodSeconds {
	case 60, 120, 300:
	default:
		return out, ErrFlowFieldCoverage
	}
	period := time.Duration(periodSeconds) * time.Second
	end := at.Truncate(period)
	out.After = TrainingWindow{Start: end.Add(-period), End: end}
	switch cadence {
	case FlowFieldPreviousPeriod:
		out.Before = TrainingWindow{Start: out.After.Start.Add(-period), End: out.After.Start}
	case FlowFieldPreviousWeek:
		out.Before = TrainingWindow{Start: out.After.Start.AddDate(0, 0, -7), End: end.AddDate(0, 0, -7)}
	default:
		return FlowFieldComparisonClocks{}, ErrFlowFieldCoverage
	}
	return out, nil
}
