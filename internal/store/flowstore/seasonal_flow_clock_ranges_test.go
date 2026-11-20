// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
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

func TestSeasonalFlowStorageQueryPrunesGapsBeforeExactMembership(t *testing.T) {
	start := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	later := start.AddDate(0, 0, 7)
	ends := []time.Time{start.Add(5 * time.Second), start.Add(7 * time.Second), start.Add(12 * time.Second), later.Add(5 * time.Second), later.Add(10 * time.Second)}
	clock, err := newSeasonalFlowClockRange(t.Context(), ends, 5*time.Second, ends[len(ends)-1], 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	windows, err := clock.exactReadWindows(t.Context())
	if err != nil || len(windows) != 2 || !windows[0].from.Equal(start) || !windows[0].to.Equal(ends[2]) ||
		!windows[1].from.Equal(later) || !windows[1].to.Equal(ends[4]) {
		t.Fatalf("storage windows filled a gap or discarded an original interval: %+v %v", windows, err)
	}
	for _, table := range []string{sharedFlowsTable, sharedFlowRollupsTable} {
		params := chParams{}
		filter, err := planFilteredCTE(flow.QueryPlan{}, table, params, flow.QueryVocabulary{}, false, windows)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(filter, " WHERE tenant_id={tenant:String} AND ") ||
			!strings.Contains(filter, ">={window_from_0:DateTime64(9,'UTC')}") ||
			!strings.Contains(filter, "<{window_to_0:DateTime64(9,'UTC')}) OR (") ||
			!strings.Contains(filter, ">={window_from_1:DateTime64(9,'UTC')}") ||
			!strings.Contains(filter, "<{window_to_1:DateTime64(9,'UTC')})) AND (") ||
			params["window_from_0"] != "2026-10-25 00:00:00" || params["window_to_0"] != "2026-10-25 00:00:12" ||
			params["window_from_1"] != "2026-11-01 00:00:00" || params["window_to_1"] != "2026-11-01 00:00:10" {
			t.Fatalf("exact intervals were not admitted inside tenant scope for %s: %s %v", table, filter, params)
		}
	}
	gap := start.Add(time.Hour)
	if first, after := clock.indices(gap); first != after {
		t.Fatal("the prefilter changed individual window membership")
	}
}
