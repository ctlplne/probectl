// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestSeasonalFlowClocksPreserveOverlapsAndGaps(t *testing.T) {
	start := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	known := []time.Time{start.Add(time.Hour), start.Add(2 * time.Hour), start.Add(5 * time.Hour), start.Add(11 * time.Hour)}
	const lookback = 2 * time.Hour
	clock, err := newSeasonalFlowClockRange(t.Context(), known, lookback, known[len(known)-1], 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	transitions, err := clock.transitions(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for delta := -2 * time.Hour; delta <= 12*time.Hour; delta += 30 * time.Minute {
		for _, diff := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
			at := start.Add(delta + diff)
			want := []int{}
			for i, end := range known {
				if !at.Before(end.Add(-lookback)) && at.Before(end) {
					want = append(want, i)
				}
			}
			first, after := clock.indices(at)
			unpack := func(lo, hi int) []int {
				indices := []int{}
				for i := lo; i < hi; i++ {
					indices = append(indices, i)
				}
				return indices
			}
			if actual := unpack(first, after); !slices.Equal(actual, want) {
				t.Fatalf("membership at %s is %v, want %v", at, actual, want)
			}
			fromTransitions := []int{}
			for _, change := range transitions {
				if change.at.After(at) {
					break
				}
				fromTransitions = unpack(change.first, change.after)
			}
			if !slices.Equal(fromTransitions, want) {
				t.Fatalf("membership after boundary at %s is %v, want %v", at, fromTransitions, want)
			}
		}
	}
}

func TestSeasonalFlowClocksRefuseMissingAndFutureBounds(t *testing.T) {
	end := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	for _, probe := range []struct {
		name   string
		ends   []time.Time
		memory int64
	}{
		{name: "empty", memory: 1 << 20},
		{name: "future", ends: []time.Time{end.Add(time.Minute)}, memory: 1 << 20},
		{name: "duplicate", ends: []time.Time{end, end}, memory: 1 << 20},
		{name: "unsorted", ends: []time.Time{end, end.Add(-time.Hour)}, memory: 1 << 20},
		{name: "budget", ends: []time.Time{end}, memory: 63},
	} {
		t.Run(probe.name, func(t *testing.T) {
			if _, err := newSeasonalFlowClockRange(t.Context(), probe.ends, time.Hour, end, probe.memory); !errors.Is(err, ErrExplorerBudget) {
				t.Fatal("an invalid clock reached the query builder", err)
			}
		})
	}
}
