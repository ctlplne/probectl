// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"testing"
	"time"
)

// capacitySeries builds a single exporter/iface bps series: `baseline` repeated
// for `n` buckets, then a final `last` bucket.
func capacitySeries(exporter string, iface uint32, n int, baseline, last float64) []CapacityPoint {
	base := time.Unix(1_700_000_000, 0).UTC()
	pts := make([]CapacityPoint, 0, n+1)
	for i := 0; i < n; i++ {
		pts = append(pts, CapacityPoint{TS: base.Add(time.Duration(i) * time.Minute), Exporter: exporter, Iface: iface, Bps: baseline})
	}
	pts = append(pts, CapacityPoint{TS: base.Add(time.Duration(n) * time.Minute), Exporter: exporter, Iface: iface, Bps: last})
	return pts
}

// TestDetectAnomaliesSurfacesCollapseEndToEnd proves AI-10 through the REAL flow
// anomaly entry point (DetectAnomaliesWithModel), not just the model: a link that
// collapses from a stable high baseline to zero is surfaced as a downward
// anomaly, and is NOT dropped by the MinBps "ignore tiny links" gate (its
// baseline is well above MinBps). A genuinely tiny link and an in-band series
// still produce nothing.
func TestDetectAnomaliesSurfacesCollapseEndToEnd(t *testing.T) {
	q := AnomalyQuery{TenantID: "tenant-a", Sensitivity: 3, MinBps: 1000}

	// A busy link (5 Mbps) that falls to 0 — an outage.
	collapse := capacitySeries("edge-1", 7, 8, 5_000_000, 0)
	got, err := DetectAnomaliesWithModel(context.Background(), collapse, q, nil)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("collapse-to-zero from a 5Mbps baseline must surface exactly one anomaly, got %d: %+v", len(got), got)
	}
	if got[0].Deviation != "down" {
		t.Fatalf("a collapse must be a downward anomaly, got deviation=%q", got[0].Deviation)
	}
	if got[0].CurrentBps != 0 || got[0].BaselineBps < q.MinBps {
		t.Fatalf("anomaly should carry current=0 and a high baseline, got current=%v baseline=%v", got[0].CurrentBps, got[0].BaselineBps)
	}

	// Non-vacuity 1: a genuinely tiny link (≈100 bps throughout, then 0) stays
	// filtered — its baseline is below MinBps, so its collapse is noise.
	tiny, err := DetectAnomaliesWithModel(context.Background(), capacitySeries("edge-2", 3, 8, 100, 0), q, nil)
	if err != nil {
		t.Fatalf("detect tiny: %v", err)
	}
	if len(tiny) != 0 {
		t.Fatalf("a sub-MinBps link collapsing must not alarm (noise), got %d: %+v", len(tiny), tiny)
	}

	// Non-vacuity 2: a stable high link that stays within its band produces no
	// anomaly (the detector is not trigger-happy).
	steady := capacitySeries("edge-3", 9, 8, 5_000_000, 5_010_000)
	quiet, err := DetectAnomaliesWithModel(context.Background(), steady, q, nil)
	if err != nil {
		t.Fatalf("detect steady: %v", err)
	}
	if len(quiet) != 0 {
		t.Fatalf("an in-band series must produce no anomaly, got %d: %+v", len(quiet), quiet)
	}
}
