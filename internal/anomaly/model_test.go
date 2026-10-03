// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLocalModelFindsMultiPlaneAnomalyWithCitations(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	var features []Feature
	for i := 6; i >= 0; i-- {
		ts := now.Add(-time.Duration(i) * time.Minute)
		bps := 10_000.0
		latency := 20.0
		if i == 0 {
			bps = 120_000
			latency = 95
		}
		l7Errors := 1.0
		if i == 0 {
			l7Errors = 37
		}
		features = append(features,
			Feature{
				TenantID: "tenant-a", Plane: "flow", Source: "edge-r1", Subject: "checkout",
				Metric: "bps", TS: ts, Value: bps, Citation: "fixtures/anomaly/tenant-a-flow.jsonl:7",
			},
			Feature{
				TenantID: "tenant-a", Plane: "metrics", Source: "synthetic", Subject: "checkout",
				Metric: "latency_ms", TS: ts, Value: latency, Citation: "fixtures/anomaly/tenant-a-metrics.jsonl:7",
			},
			Feature{
				TenantID: "tenant-a", Plane: "ebpf", Source: "host-agent", Subject: "checkout",
				Metric: "l7_errors", TS: ts, Value: l7Errors, Citation: "fixtures/anomaly/tenant-a-ebpf.jsonl:7",
			},
		)
	}

	findings, err := NewLocalZScoreModel().Evaluate(context.Background(), features, Query{TenantID: "tenant-a", Sensitivity: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a learned anomaly")
	}
	got := findings[0]
	if got.Model != "local-zscore-v1" {
		t.Fatalf("model = %q", got.Model)
	}
	if got.TrainingWindow.Samples != 6 || got.TrainingWindow.Start.IsZero() || got.TrainingWindow.End.IsZero() {
		t.Fatalf("training window = %+v", got.TrainingWindow)
	}
	if len(got.Citations) == 0 {
		t.Fatalf("missing citations: %+v", got)
	}
	if got.Features["flow.bps"] != 120_000 || got.Features["metrics.latency_ms"] != 95 || got.Features["ebpf.l7_errors"] != 37 {
		t.Fatalf("multi-plane features = %+v", got.Features)
	}
}

// TestLocalModelFlagsCollapseToZero is the AI-10 regression: the local z-score
// model used to score only upward deviations, so a metric collapsing from a
// stable non-zero baseline to zero (an outage) produced a negative score that
// was silently dropped. The two collapse subtests assert the drop now surfaces
// (direction "down"); the in-band subtest is the non-vacuity guard that the
// two-sided score is not merely trigger-happy. Before the model.go fix the two
// collapse subtests fail with "yielded no finding".
func TestLocalModelFlagsCollapseToZero(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)

	// series builds a single-subject bps series, oldest first, one minute
	// apart, so the newest sample (the one scored) is last.
	series := func(values ...float64) []Feature {
		out := make([]Feature, 0, len(values))
		n := len(values)
		for i, v := range values {
			out = append(out, Feature{
				TenantID: "tenant-a", Plane: "flow", Source: "edge-r1", Subject: "uplink",
				Metric: "bps", TS: now.Add(-time.Duration(n-1-i) * time.Minute), Value: v,
				Citation: "fixtures/anomaly/tenant-a-collapse.jsonl:1",
			})
		}
		return out
	}
	eval := func(t *testing.T, feats []Feature) []Finding {
		t.Helper()
		findings, err := NewLocalZScoreModel().Evaluate(context.Background(), feats, Query{TenantID: "tenant-a", Sensitivity: 3})
		if err != nil {
			t.Fatal(err)
		}
		return findings
	}

	t.Run("collapse from jittery non-zero baseline is flagged downward", func(t *testing.T) {
		// A stable ~1000 bps link with normal jitter that falls to 0: a classic
		// outage, and the std>0 path the old one-sided z-score dropped.
		findings := eval(t, series(1000, 1010, 990, 1005, 995, 0))
		if len(findings) < 1 {
			t.Fatalf("collapse to zero yielded no finding: %+v", findings)
		}
		if got := findings[0]; got.Direction != "down" {
			t.Fatalf("direction = %q, want \"down\" (current=%v baseline=%v)", got.Direction, got.Current, got.Baseline)
		}
	})

	t.Run("collapse from perfectly flat baseline is flagged downward", func(t *testing.T) {
		// std == 0 exercises the zero-stddev branch, which used to fire only on
		// an upward jump; a collapse to zero from a non-zero mean must fire too.
		findings := eval(t, series(1000, 1000, 1000, 1000, 0))
		if len(findings) < 1 {
			t.Fatalf("collapse from flat baseline yielded no finding: %+v", findings)
		}
		if got := findings[0]; got.Direction != "down" {
			t.Fatalf("direction = %q, want \"down\"", got.Direction)
		}
	})

	t.Run("in-band jitter is not trigger-happy", func(t *testing.T) {
		// Non-vacuity guard: a noisy-but-stable series whose final sample stays
		// inside the normal band must produce NO finding.
		findings := eval(t, series(980, 1020, 990, 1010, 1000, 1005))
		if len(findings) != 0 {
			t.Fatalf("in-band jitter produced %d finding(s), want 0: %+v", len(findings), findings)
		}
	})
}

func TestLocalModelRefusesCrossTenantFeatures(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	features := []Feature{
		{TenantID: "tenant-a", Plane: "flow", Subject: "checkout", Metric: "bps", TS: now.Add(-3 * time.Minute), Value: 10},
		{TenantID: "tenant-a", Plane: "flow", Subject: "checkout", Metric: "bps", TS: now.Add(-2 * time.Minute), Value: 10},
		{TenantID: "tenant-b", Plane: "flow", Subject: "checkout", Metric: "bps", TS: now.Add(-time.Minute), Value: 10},
		{TenantID: "tenant-a", Plane: "flow", Subject: "checkout", Metric: "bps", TS: now, Value: 100},
	}
	_, err := NewLocalZScoreModel().Evaluate(context.Background(), features, Query{TenantID: "tenant-a"})
	if !errors.Is(err, ErrCrossTenantFeature) {
		t.Fatalf("error = %v, want ErrCrossTenantFeature", err)
	}
}
