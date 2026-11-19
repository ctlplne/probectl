// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"testing"
	"time"
)

func TestHourlySeasonalFlowUsesTheLatestFullyCompletedCivilMinute(t *testing.T) {
	model, err := NewWeeklySeasonalModel(WeeklySeasonalConfig{
		Cadence: SeasonalHourly, Timezone: "America/New_York", MinimumDays: 3, MinimumDeviation: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, clock, end string
	}{
		{"ordinary", "2026-10-31T12:15:47Z", "2026-10-31T12:15:00Z"},
		{"first folded hour", "2026-11-01T05:30:47Z", "2026-11-01T05:00:00Z"},
		{"second folded hour", "2026-11-01T06:30:47Z", "2026-11-01T06:30:00Z"},
		{"spring transition", "2026-03-08T07:00:15Z", "2026-03-08T07:00:00Z"},
	} {
		t.Run(row.name, func(t *testing.T) {
			at, err := time.Parse(time.RFC3339, row.clock)
			if err != nil {
				t.Fatal(err)
			}
			want, err := time.Parse(time.RFC3339, row.end)
			if err != nil {
				t.Fatal(err)
			}
			observed, end := model.LatestCompletedSlot(at)
			if !end.Equal(want) || !observed.Equal(end.Add(-time.Millisecond)) {
				t.Fatalf("got observation %s exclusive end %s, want end %s", observed, end, want)
			}
			for _, before := range model.ComparableCompleteEnds(observed) {
				if !before.Before(end) || !model.ComparableSample(before.Add(-time.Millisecond), observed) {
					t.Fatal("training end disagrees with its actual local-minute population", before)
				}
			}
		})
	}
}
