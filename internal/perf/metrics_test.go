// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package perf

import (
	"testing"
	"time"
)

func TestPercentileNearestRank(t *testing.T) {
	// 1..100 ms; nearest-rank: p50 -> rank 50 -> 50ms, p95 -> 55... rank 95 -> 95ms.
	var l Latencies
	for i := 1; i <= 100; i++ {
		l.Record(time.Duration(i) * time.Millisecond)
	}
	s := l.Summary()
	cases := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"count", time.Duration(s.Count), 100},
		{"min", s.Min, 1 * time.Millisecond},
		{"max", s.Max, 100 * time.Millisecond},
		{"p50", s.P50, 50 * time.Millisecond},
		{"p95", s.P95, 95 * time.Millisecond},
		{"p99", s.P99, 99 * time.Millisecond},
		{"mean", s.Mean, 50*time.Millisecond + 500*time.Microsecond},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestSummaryEmpty(t *testing.T) {
	var l Latencies
	if s := l.Summary(); s.Count != 0 || s.P95 != 0 {
		t.Fatalf("empty summary = %+v, want zero", s)
	}
}

func TestLatenciesAddMerge(t *testing.T) {
	var a, b Latencies
	a.Record(10 * time.Millisecond)
	b.Record(20 * time.Millisecond)
	b.Record(30 * time.Millisecond)
	a.Add(&b)
	if s := a.Summary(); s.Count != 3 || s.Max != 30*time.Millisecond {
		t.Fatalf("merged = %+v, want count 3 max 30ms", s)
	}
}

func TestPercentileSingleSample(t *testing.T) {
	var l Latencies
	l.Record(7 * time.Millisecond)
	s := l.Summary()
	if s.P50 != 7*time.Millisecond || s.P95 != 7*time.Millisecond || s.P99 != 7*time.Millisecond {
		t.Fatalf("single-sample percentiles = %+v", s)
	}
}

func TestChunkPartition(t *testing.T) {
	// 10 items across 3 producers → 4,3,3, contiguous and covering [0,10).
	got := [][2]int{}
	for i := 0; i < 3; i++ {
		lo, hi := chunk(10, 3, i)
		got = append(got, [2]int{lo, hi})
	}
	want := [][2]int{{0, 4}, {4, 7}, {7, 10}}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("chunk %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestIngestConfigTotal(t *testing.T) {
	c := IngestConfig{Tenants: 2, AgentsPerTenant: 3, TestsPerAgent: 4, ResultsPerTest: 5}
	if c.TotalResults() != 120 {
		t.Fatalf("total = %d, want 120", c.TotalResults())
	}
}

func TestBaselineChecks(t *testing.T) {
	b := Baseline{MinIngestThroughput: 1000, MaxPooledQueryP95: 100 * time.Millisecond}

	if v := b.CheckIngest(IngestReport{Throughput: 5000}); len(v) != 0 {
		t.Errorf("healthy ingest flagged: %v", v)
	}
	if v := b.CheckIngest(IngestReport{Throughput: 500}); len(v) != 1 {
		t.Errorf("slow ingest not flagged: %v", v)
	}

	if v := b.CheckPooled(PooledReport{IsolationOK: true, Latency: LatencyStat{P95: 50 * time.Millisecond}}); len(v) != 0 {
		t.Errorf("healthy pooled flagged: %v", v)
	}
	// Broken isolation is always a violation, regardless of latency.
	bad := b.CheckPooled(PooledReport{IsolationOK: false, Mismatches: 3, Queries: 100, Latency: LatencyStat{P95: 10 * time.Millisecond}})
	if len(bad) != 1 {
		t.Errorf("broken isolation not flagged: %v", bad)
	}
	slow := b.CheckPooled(PooledReport{IsolationOK: true, Latency: LatencyStat{P95: 300 * time.Millisecond}})
	if len(slow) != 1 {
		t.Errorf("slow pooled query not flagged: %v", slow)
	}
}
