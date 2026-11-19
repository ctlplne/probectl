// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"time"
)

// LatestCompletedSlot returns the latest complete civil hour, or minute for
// the hourly profile. Both occurrences of a folded slot must finish. The
// observation is stamped just before its exclusive UTC end for civil grouping.
func (m WeeklySeasonalModel) LatestCompletedSlot(at time.Time) (observed, end time.Time) {
	if m.location == nil || at.IsZero() {
		return time.Time{}, time.Time{}
	}
	local := at.In(m.location)
	if m.cadence == SeasonalHourly {
		return m.latestCompletedMinute(local, at)
	}
	wall := time.Date(local.Year(), local.Month(), local.Day(), local.Hour(), 0, 0, 0, time.UTC)
	for civil := wall; ; civil = civil.Add(-time.Hour) {
		candidates := m.appendLocalHour(nil, civil)
		if len(candidates) == 0 {
			continue
		}
		last := candidates[len(candidates)-1].End
		if last.After(at) {
			continue
		}
		return last.Add(-time.Millisecond), last
	}
}

func (m WeeklySeasonalModel) latestCompletedMinute(local, at time.Time) (time.Time, time.Time) {
	wall := seasonalWall(local).Add(time.Duration(local.Minute()) * time.Minute)
	for civil := wall; ; civil = civil.Add(-time.Minute) {
		candidates := m.appendLocalMinute(nil, civil.Truncate(time.Hour), civil.Minute())
		if len(candidates) > 0 {
			last := candidates[len(candidates)-1].End
			if !last.After(at) {
				return last.Add(-time.Millisecond), last
			}
		}
	}
}

// SeasonalFlowMaximumWindows bounds both offset intervals of every civil
// hour across the training span and includes the current observation.
const SeasonalFlowMaximumWindows = 2*seasonalTrainingDays*24 + 1

// ComparableCompleteEnds pins the equivalent prior local slots by their exact
// exclusive UTC ends. Both ends in a repeated hour remain distinct inputs,
// while the model treats their shared date as one training date.
func (m WeeklySeasonalModel) ComparableCompleteEnds(observation time.Time) []time.Time {
	windows := m.ComparableWindows(observation)
	out := make([]time.Time, 0, len(windows))
	for _, window := range windows {
		out = append(out, window.End)
	}
	return out
}
