// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package perf

import (
	"fmt"
	"time"
)

// Baseline is the checked-in regression guard: floors and ceilings the perf
// smoke asserts against. The values are deliberately generous (a smoke, not a
// soak) so they catch order-of-magnitude regressions — a pooled-tenancy
// cardinality or RLS-cost blow-up — not ordinary CI jitter. See
// docs/perf-baseline.md for the recorded GA (M6) numbers behind them.
type Baseline struct {
	// MinIngestThroughput is the floor for end-to-end results/sec on the
	// lightweight ingest path (publish → confirmed in the TSDB).
	MinIngestThroughput float64
	// MaxPooledQueryP95 is the ceiling for a tenant-scoped query's p95 latency
	// under mixed multi-tenant load (the RLS-cost early-warning).
	MaxPooledQueryP95 time.Duration
}

// m6Baseline is the GA (M6) regression-guard baseline the perf smoke asserts
// against. The floors/ceilings are calibrated from the recorded CI numbers in
// docs/perf-baseline.md with generous headroom, so the smoke catches an
// order-of-magnitude regression (a pooled-cardinality or RLS-cost blow-up), not
// ordinary CI jitter. Update both this and the doc together when the numbers
// move materially.
func m6Baseline() Baseline {
	return Baseline{
		MinIngestThroughput: 3000, // results/sec on the lightweight ingest path
		MaxPooledQueryP95:   250 * time.Millisecond,
	}
}

// checkIngest returns human-readable threshold violations for an ingest run
// (empty = within baseline).
func (b Baseline) checkIngest(r IngestReport) []string {
	var v []string
	if b.MinIngestThroughput > 0 && r.Throughput < b.MinIngestThroughput {
		v = append(v, fmt.Sprintf("ingest throughput %.0f results/s is below the %.0f results/s floor",
			r.Throughput, b.MinIngestThroughput))
	}
	return v
}

// checkPooled returns threshold/correctness violations for a pooled run. A broken
// isolation result is always a violation (correctness, not just latency).
func (b Baseline) checkPooled(r PooledReport) []string {
	var v []string
	if !r.IsolationOK {
		v = append(v, fmt.Sprintf("tenant isolation broken under load: %d/%d queries returned the wrong row count",
			r.Mismatches, r.Queries))
	}
	if b.MaxPooledQueryP95 > 0 && r.Latency.P95 > b.MaxPooledQueryP95 {
		v = append(v, fmt.Sprintf("pooled tenant-scoped query p95 %s exceeds the %s ceiling",
			round(r.Latency.P95), b.MaxPooledQueryP95))
	}
	return v
}
