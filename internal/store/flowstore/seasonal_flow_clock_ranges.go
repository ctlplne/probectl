// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"slices"
	"sort"
	"time"
)

// seasonalFlowClockRange maps one ordered set of clock windows with a common
// lookback. A flow can be present in several windows when the view overlaps.
type seasonalFlowClockRange struct {
	ends     []time.Time
	lookback time.Duration
}

func newSeasonalFlowClockRange(ctx context.Context, ends []time.Time, lookback time.Duration, asOf time.Time, memory int64) (seasonalFlowClockRange, error) {
	if lookback <= 0 || len(ends) == 0 || asOf.IsZero() || int64(len(ends)) > memory/1024 {
		return seasonalFlowClockRange{}, ErrExplorerBudget
	}
	for i, end := range ends {
		if err := ctx.Err(); err != nil {
			return seasonalFlowClockRange{}, err
		}
		if end.IsZero() || end.After(asOf) || (i > 0 && !end.After(ends[i-1])) {
			return seasonalFlowClockRange{}, ErrExplorerBudget
		}
	}
	return seasonalFlowClockRange{ends: slices.Clone(ends), lookback: lookback}, nil
}

// indices returns precisely the windows whose half-open interval contains at.
// Membership can be charged before materializing any per-window work.
func (r seasonalFlowClockRange) indices(at time.Time) (first, after int) {
	first = sort.Search(len(r.ends), func(i int) bool { return r.ends[i].After(at) })
	lastPossibleEnd := at.Add(r.lookback)
	after = first + sort.Search(len(r.ends)-first, func(i int) bool { return r.ends[first+i].After(lastPossibleEnd) })
	return first, after
}

// A transition records the range of active window indices immediately after
// a clock boundary. A row at the boundary observes this new membership.
type seasonalFlowClockTransition struct {
	at    time.Time
	first int
	after int
}

func (r seasonalFlowClockRange) transitions(ctx context.Context) ([]seasonalFlowClockTransition, error) {
	times := make([]time.Time, 0, len(r.ends))
	times = append(times, r.ends...)
	for _, end := range r.ends {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		times = append(times, end.Add(-r.lookback))
	}
	slices.SortFunc(times, time.Time.Compare)
	times = slices.CompactFunc(times, time.Time.Equal)
	transitions := make([]seasonalFlowClockTransition, 0, len(times))
	for _, at := range times {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		first, after := r.indices(at)
		transitions = append(transitions, seasonalFlowClockTransition{at: at, first: first, after: after})
	}
	return transitions, nil
}

// seasonalReadWindow is one contiguous storage interval. The membership join
// still decides which individual analysis windows receive each original row.
type seasonalReadWindow struct {
	from, to time.Time
}

// exactReadWindows merges overlapping and adjacent windows, so storage can
// exclude the gaps before loading any original telemetry. Large fragmented
// requests keep the ordinary enclosing range and existing membership filter.
func (r seasonalFlowClockRange) exactReadWindows(ctx context.Context) ([]seasonalReadWindow, error) {
	const maxSQLIntervals = 64
	var windows []seasonalReadWindow
	for _, end := range r.ends {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		start := end.Add(-r.lookback)
		last := len(windows) - 1
		if last >= 0 && !start.After(windows[last].to) {
			windows[last].to = end
			continue
		}
		if len(windows) == maxSQLIntervals {
			return nil, nil
		}
		windows = append(windows, seasonalReadWindow{from: start, to: end})
	}
	return windows, nil
}
