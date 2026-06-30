// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
		features = append(features,
			Feature{
				TenantID: "tenant-a", Plane: "flow", Source: "edge-r1", Subject: "checkout",
				Metric: "bps", TS: ts, Value: bps, Citation: "fixtures/anomaly/tenant-a-flow.jsonl:7",
			},
			Feature{
				TenantID: "tenant-a", Plane: "metrics", Source: "synthetic", Subject: "checkout",
				Metric: "latency_ms", TS: ts, Value: latency, Citation: "fixtures/anomaly/tenant-a-metrics.jsonl:7",
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
	if got.Features["flow.bps"] != 120_000 || got.Features["metrics.latency_ms"] != 95 {
		t.Fatalf("multi-plane features = %+v", got.Features)
	}
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
