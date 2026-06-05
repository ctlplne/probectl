package perf

import (
	"context"
	"os"
	"testing"
	"time"
)

// The CI-scale gate run: proves the GATE end to end (profiles drive, SLOs
// evaluate, noisy-neighbor isolation holds) on every CI pass. The full-scale
// L/XL run is `make scale-gate TIER=L` on reference hardware (PROBECTL_SCALE_TIER
// + PROBECTL_SCALE=1) — its numbers are recorded in docs/scale-gate.md.
func TestScaleGateCI(t *testing.T) {
	tier := Tier(os.Getenv("PROBECTL_SCALE_TIER"))
	scale := 0.05 // CI: tiny load shape, full multi-tenant structure
	if tier == "" {
		tier = TierM
	}
	if os.Getenv("PROBECTL_SCALE") == "1" {
		scale = 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rep, err := RunScaleGate(ctx, tier, scale)
	if err != nil {
		t.Fatalf("scale gate %s: %v", tier, err)
	}
	t.Logf("tier=%s ci=%t %s", rep.Profile.Tier, rep.AtCIScale, rep.Ingest)
	if rep.Noisy.Ran {
		t.Logf("%s", rep.Noisy)
	}

	if len(rep.Violations) > 0 {
		t.Fatalf("SCALE GATE FAILED:\n%v", rep.Violations)
	}
	// The noisy-neighbor scenario must have actually run for multi-tenant tiers.
	if rep.Profile.Ingest.Tenants > 1 && !rep.Noisy.Ran {
		t.Fatal("multi-tenant tier must run the noisy-neighbor scenario")
	}
	if rep.Noisy.Ran && !rep.Noisy.QuietCorrect {
		t.Fatal("quiet-tenant correctness must hold under a flooding neighbor (F57)")
	}
}

func TestProfilesShapeAndScaling(t *testing.T) {
	full := Profiles(1)
	if len(full) != 4 {
		t.Fatalf("want 4 reference tiers, got %d", len(full))
	}
	// Tier ordering of ambition: S < M < L < XL by total results.
	for i := 1; i < len(full); i++ {
		if full[i].Ingest.TotalResults() <= full[i-1].Ingest.TotalResults() {
			t.Errorf("tier %s must be larger than %s", full[i].Tier, full[i-1].Tier)
		}
	}
	// CI downscaling keeps the multi-tenant structure intact.
	ci := Profiles(0.05)
	for i, p := range ci {
		if p.Ingest.Tenants != full[i].Ingest.Tenants {
			t.Errorf("%s: scaling must not change the tenant structure (%d → %d)",
				p.Tier, full[i].Ingest.Tenants, p.Ingest.Tenants)
		}
		if p.Ingest.TotalResults() >= full[i].Ingest.TotalResults() {
			t.Errorf("%s: CI scale must shrink the load", p.Tier)
		}
	}
	// Every multi-tenant tier carries the F57 inflation ceiling.
	for _, p := range full[1:] {
		if p.SLO.MaxNoisyInflation <= 0 {
			t.Errorf("%s: missing the noisy-neighbor SLO (F57)", p.Tier)
		}
	}
	if _, err := ProfileFor("XXL", 1); err == nil {
		t.Error("unknown tier must error")
	}
}

func TestNoisyNeighborIsolationAndBoundedInflation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rep, err := DriveNoisyNeighbor(ctx, NoisyConfig{
		QuietResults: 400, NoisyFactor: 10, Producers: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s", rep)
	if !rep.Ran {
		t.Fatal("scenario must report it ran")
	}
	// CORRECTNESS is the hard assertion: the quiet tenant's results all land,
	// correctly scoped, regardless of the neighbor's flood.
	if !rep.QuietCorrect {
		t.Fatalf("quiet-tenant correctness broke under noise: %+v", rep)
	}
	if rep.NoisySeries == 0 {
		t.Fatal("the noisy tenant must actually have flooded")
	}
	if rep.Inflation < 1 {
		t.Fatalf("inflation must be clamped ≥ 1, got %.2f", rep.Inflation)
	}
}

func TestScaleSLOEvaluation(t *testing.T) {
	p, err := ProfileFor(TierM, 1)
	if err != nil {
		t.Fatal(err)
	}
	// A full-scale report violating every SLO trips every check (the noisy
	// p95 is material, so the inflation ratio applies).
	rep := ScaleReport{
		Profile:   p,
		AtCIScale: false,
		Ingest: IngestReport{
			Throughput:     p.SLO.MinIngestThroughput / 2,
			PublishLatency: LatencyStat{P95: p.SLO.MaxPublishP95 * 3},
		},
		Noisy: NoisyReport{Ran: true, QuietCorrect: false,
			Inflation: p.SLO.MaxNoisyInflation * 2, NoisyP95: 50 * time.Millisecond},
	}
	rep.evaluate()
	if len(rep.Violations) != 4 {
		t.Fatalf("want 4 violations (throughput, p95, correctness, inflation), got %d: %v",
			len(rep.Violations), rep.Violations)
	}
	// At CI scale the absolute floors don't apply — the ratio + correctness do.
	ci := ScaleReport{Profile: p, AtCIScale: true, Ingest: rep.Ingest, Noisy: rep.Noisy}
	ci.evaluate()
	if len(ci.Violations) != 2 {
		t.Fatalf("CI scale: want 2 violations (correctness, inflation), got %v", ci.Violations)
	}
	// Sub-materiality "inflation" is scheduler noise, never a violation: a
	// 100x ratio of microseconds is an excellent experience.
	noise := ScaleReport{Profile: p, AtCIScale: true,
		Noisy: NoisyReport{Ran: true, QuietCorrect: true, Inflation: 100, NoisyP95: 200 * time.Microsecond}}
	noise.evaluate()
	if len(noise.Violations) != 0 {
		t.Fatalf("sub-materiality inflation must not violate, got %v", noise.Violations)
	}
}
