// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tsdb

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/ctlplne/probectl/internal/breaker"
	"github.com/ctlplne/probectl/internal/store/chclient"
)

// Breaker parity between the TSDB remote-write path and the ClickHouse stores
// (Foundation-Loop S-df881186).
//
// Four ClickHouse-backed stores were deliberately consolidated onto one
// breaker-guarded transport; the TSDB kept a parallel breaker and its own copy
// of the 5xx/429 classification, so the per-target-breaker fix landed for silos
// and not for metrics. These tests drive the SAME fault sequence through both
// and require the same breaker state, rather than asserting the TSDB's behavior
// in isolation — isolated assertions are how the two drifted in the first place.

// statusTripper answers every request with a fixed status.
type statusTripper struct {
	status int
	calls  *int
}

func (t statusTripper) RoundTrip(*http.Request) (*http.Response, error) {
	*t.calls++
	return &http.Response{
		StatusCode: t.status,
		Body:       io.NopCloser(bytes.NewReader(nil)),
		Header:     make(http.Header),
	}, nil
}

// driveTSDB issues n remote-write attempts and returns the breaker snapshot.
func driveTSDB(t *testing.T, status string, code, n int) (breaker.Stats, int) {
	t.Helper()
	calls := 0
	p := NewPrometheusWithClient("http://tsdb.invalid", &http.Client{
		Transport: statusTripper{status: code, calls: &calls},
	})
	for range n {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, p.url, nil)
		if err != nil {
			t.Fatalf("%s: %v", status, err)
		}
		if resp, err := p.promDo(req); err == nil && resp != nil {
			_ = resp.Body.Close()
		}
	}
	return p.BreakerStats(), calls
}

// driveCH issues the same n attempts through a ClickHouse-store-shaped caller.
func driveCH(t *testing.T, status string, code, n int) (breaker.Stats, int) {
	t.Helper()
	calls := 0
	conn := chclient.NewWithClient(&http.Client{
		Transport: statusTripper{status: code, calls: &calls},
	})
	const base = "http://clickhouse.invalid"
	for range n {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/", nil)
		if err != nil {
			t.Fatalf("%s: %v", status, err)
		}
		if resp, err := conn.Do(base, req); err == nil && resp != nil {
			_ = resp.Body.Close()
		}
	}
	return conn.BreakerFor(base).Stats(), calls
}

func TestTSDBBreakerMatchesClickHouseStoresUnderFault(t *testing.T) {
	// 8 attempts against a breaker whose default threshold is 5: the first 5
	// reach the upstream and trip it, the last 3 short-circuit.
	const attempts = 8
	cases := []struct {
		name string
		code int
	}{
		{"5xx server error", http.StatusInternalServerError},
		{"503 unavailable", http.StatusServiceUnavailable},
		{"429 overload", http.StatusTooManyRequests},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tsdbStats, tsdbCalls := driveTSDB(t, tc.name, tc.code, attempts)
			chStats, chCalls := driveCH(t, tc.name, tc.code, attempts)

			if tsdbStats.State != chStats.State {
				t.Errorf("state: tsdb=%q clickhouse=%q — the two transports disagree about whether the upstream is down",
					tsdbStats.State, chStats.State)
			}
			if tsdbStats.Trips != chStats.Trips {
				t.Errorf("trips: tsdb=%d clickhouse=%d", tsdbStats.Trips, chStats.Trips)
			}
			if tsdbStats.ShortCircuits != chStats.ShortCircuits {
				t.Errorf("short-circuits: tsdb=%d clickhouse=%d", tsdbStats.ShortCircuits, chStats.ShortCircuits)
			}
			if tsdbCalls != chCalls {
				t.Errorf("upstream calls: tsdb=%d clickhouse=%d — one path is still hitting a known-down backend",
					tsdbCalls, chCalls)
			}
			// Anchor the shared expectation so "equal" cannot mean "both broken".
			if tsdbStats.State != breaker.StateOpen {
				t.Errorf("state = %q after %d faults, want open", tsdbStats.State, attempts)
			}
			if tsdbCalls != 5 {
				t.Errorf("upstream calls = %d, want 5 (the default threshold) — the rest must short-circuit", tsdbCalls)
			}
		})
	}
}

// A 4xx is the caller's problem, not the upstream's: neither transport may
// count it against the breaker, or one malformed sample would take metrics
// ingestion down.
func TestTSDBAndClickHouseAgreeThat4xxIsNotAnUpstreamFault(t *testing.T) {
	const attempts = 8
	tsdbStats, tsdbCalls := driveTSDB(t, "400", http.StatusBadRequest, attempts)
	chStats, chCalls := driveCH(t, "400", http.StatusBadRequest, attempts)

	if tsdbStats.State != chStats.State || tsdbStats.Trips != chStats.Trips {
		t.Errorf("4xx handling diverges: tsdb=%+v clickhouse=%+v", tsdbStats, chStats)
	}
	if tsdbStats.State != breaker.StateClosed || tsdbStats.Trips != 0 {
		t.Errorf("a 4xx must not trip the breaker: %+v", tsdbStats)
	}
	if tsdbCalls != attempts || chCalls != attempts {
		t.Errorf("every 4xx attempt must reach the upstream: tsdb=%d clickhouse=%d", tsdbCalls, chCalls)
	}
}

// The TSDB must not keep a breaker of its own beside the shared one: two
// breakers is the state this finding removed, and BreakerStats reporting a
// different breaker than Do consults is how that state hides.
func TestTSDBBreakerStatsReportsTheBreakerDoUses(t *testing.T) {
	calls := 0
	p := NewPrometheusWithClient("http://tsdb.invalid", &http.Client{
		Transport: statusTripper{status: http.StatusInternalServerError, calls: &calls},
	})
	for range 5 {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, p.url, nil)
		if resp, err := p.promDo(req); err == nil && resp != nil {
			_ = resp.Body.Close()
		}
	}
	if got := p.BreakerStats(); got.State != breaker.StateOpen || got.Trips != 1 {
		t.Fatalf("BreakerStats = %+v after 5 faults through promDo; it is reporting a different "+
			"breaker than Do consults, so the fallback metric would say healthy while writes short-circuit", got)
	}
}
