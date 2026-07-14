// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package perf

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// LatencyStat is a summary of a set of latency samples.
type LatencyStat struct {
	Count int
	Min   time.Duration
	Mean  time.Duration
	P50   time.Duration
	P95   time.Duration
	P99   time.Duration
	Max   time.Duration
}

// String renders the stat compactly for logs and the baseline doc.
func (s LatencyStat) String() string {
	return fmt.Sprintf("n=%d min=%s p50=%s p95=%s p99=%s max=%s mean=%s",
		s.Count, round(s.Min), round(s.P50), round(s.P95), round(s.P99), round(s.Max), round(s.Mean))
}

// Latencies collects latency samples and summarizes them. It is safe for
// concurrent Record from multiple workers (the load drivers fan out).
type Latencies struct {
	mu      sync.Mutex
	samples []time.Duration
}

// Record adds one sample.
func (l *Latencies) Record(d time.Duration) {
	l.mu.Lock()
	l.samples = append(l.samples, d)
	l.mu.Unlock()
}

// Add merges another collector's samples into this one.
func (l *Latencies) Add(other *Latencies) {
	other.mu.Lock()
	s := append([]time.Duration(nil), other.samples...)
	other.mu.Unlock()

	l.mu.Lock()
	l.samples = append(l.samples, s...)
	l.mu.Unlock()
}

// Summary computes the percentile/min/max/mean summary. Percentiles use the
// nearest-rank method on the sorted samples. An empty collector yields a
// zero-valued stat.
func (l *Latencies) Summary() LatencyStat {
	l.mu.Lock()
	sorted := append([]time.Duration(nil), l.samples...)
	l.mu.Unlock()

	if len(sorted) == 0 {
		return LatencyStat{}
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var sum time.Duration
	for _, d := range sorted {
		sum += d
	}
	return LatencyStat{
		Count: len(sorted),
		Min:   sorted[0],
		Max:   sorted[len(sorted)-1],
		Mean:  sum / time.Duration(len(sorted)),
		P50:   percentile(sorted, 50),
		P95:   percentile(sorted, 95),
		P99:   percentile(sorted, 99),
	}
}

// percentile returns the p-th percentile (0–100) of an ascending-sorted slice
// using the nearest-rank method: rank = ceil(p/100 * n), 1-indexed.
func percentile(sorted []time.Duration, p float64) time.Duration {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[n-1]
	}
	rank := int(p/100*float64(n) + 0.9999999) // ceil
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return sorted[rank-1]
}

// round trims a duration to a readable precision for reporting.
func round(d time.Duration) time.Duration {
	switch {
	case d >= time.Second:
		return d.Round(time.Millisecond)
	case d >= time.Millisecond:
		return d.Round(10 * time.Microsecond)
	default:
		return d.Round(time.Microsecond)
	}
}
