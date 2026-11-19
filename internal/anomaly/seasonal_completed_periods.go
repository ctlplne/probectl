// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"time"
)

// LatestCompletedSlot returns the latest fully completed local clock hour.
// Repeated offset ranges for the same hour both have to be complete. The
// observation is stamped just before its exclusive UTC end for civil grouping.
func (m WeeklySeasonalModel) LatestCompletedSlot(at time.Time) (observed, end time.Time) {
	if m.location == nil || at.IsZero() {
		return time.Time{}, time.Time{}
	}
	local := at.In(m.location)
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

// SeasonalFlowMaximumWindows includes each daily comparison date, both
// offset intervals of folded civil hours and the current observation.
const SeasonalFlowMaximumWindows = 2*seasonalTrainingDays + 1

// ComparableCompleteEnds pins the equivalent prior local hours by their exact
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
