package perf

// The S48 L/XL scale gate: the S/M/L/XL reference-architecture load profiles
// (PRD §5.4), the numeric SLOs they are validated against, and the
// multi-tenant NOISY-NEIGHBOR scenario (one tenant flooding must not bleed
// into another tenant's experience — F57, the M14 milestone line).
//
// ⚠ The numeric SLO targets are PROVISIONAL. CLAUDE.md §2 lists numeric SLO
// targets as a human-owned open decision: these values are engineering
// estimates recorded so the gate is runnable end to end, awaiting explicit
// sign-off in docs/scale-gate.md. Change them there and here together.
//
// Two run scales, one harness:
//   - CI scale (Scale < 1): a downscaled smoke proving the GATE itself —
//     profiles drive, SLOs evaluate, noisy-neighbor isolation holds. Runs in
//     every CI pass.
//   - Full scale (Scale = 1): the acquirer-grade run on reference hardware
//     (make scale-gate TIER=L). Numbers recorded in docs/scale-gate.md.

import (
	"context"
	"fmt"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// Tier names a PRD §5.4 reference architecture.
type Tier string

// The reference tiers (PRD §5.4).
const (
	TierS  Tier = "S"  // homelab/compose, single-tenant, ≤~25 agents
	TierM  Tier = "M"  // HA K8s, small pooled multi-tenant, hundreds of agents
	TierL  Tier = "L"  // sharded, pooled many-tenant, thousands of agents
	TierXL Tier = "XL" // MSP-scale pooled+siloed mix, tens of thousands of agents
)

// ScaleSLO is the numeric gate for one tier — PROVISIONAL (see the package
// note): recorded so the gate runs, awaiting human sign-off.
type ScaleSLO struct {
	// MinIngestThroughput floors end-to-end results/sec at full scale.
	MinIngestThroughput float64
	// MaxPublishP95 ceilings the producer-side publish latency.
	MaxPublishP95 time.Duration
	// MaxNoisyInflation ceilings the noisy-neighbor effect: the quiet
	// tenant's p95 under a flooding neighbor divided by its solo p95.
	// (F57: no cross-tenant performance bleed.)
	MaxNoisyInflation float64
}

// Profile is one tier's load shape at full scale.
type Profile struct {
	Tier    Tier
	Ingest  IngestConfig
	SLO     ScaleSLO
	Comment string
}

// Profiles returns the reference profiles. Scale (0 < s ≤ 1) downscales the
// load shape for CI runs while keeping the multi-tenant structure intact —
// the CI run proves the GATE; the full-scale run proves the PLATFORM.
func Profiles(scale float64) []Profile {
	if scale <= 0 || scale > 1 {
		scale = 1
	}
	s := func(n int) int {
		v := int(float64(n) * scale)
		if v < 1 {
			v = 1
		}
		return v
	}
	return []Profile{
		{
			Tier: TierS,
			Ingest: IngestConfig{
				Tenants: 1, AgentsPerTenant: s(25), TestsPerAgent: 4,
				ResultsPerTest: s(40), Producers: 4, SettleTimeout: 60 * time.Second,
			},
			SLO:     ScaleSLO{MinIngestThroughput: 1500, MaxPublishP95: 50 * time.Millisecond, MaxNoisyInflation: 0}, // single-tenant: no neighbor
			Comment: "homelab/compose single-tenant",
		},
		{
			Tier: TierM,
			Ingest: IngestConfig{
				Tenants: 8, AgentsPerTenant: s(40), TestsPerAgent: 4,
				ResultsPerTest: s(40), Producers: 8, SettleTimeout: 90 * time.Second,
			},
			SLO:     ScaleSLO{MinIngestThroughput: 3000, MaxPublishP95: 50 * time.Millisecond, MaxNoisyInflation: 2},
			Comment: "HA small pooled multi-tenant",
		},
		{
			Tier: TierL,
			Ingest: IngestConfig{
				Tenants: 32, AgentsPerTenant: s(100), TestsPerAgent: 5,
				ResultsPerTest: s(40), Producers: 16, SettleTimeout: 5 * time.Minute,
			},
			SLO:     ScaleSLO{MinIngestThroughput: 10000, MaxPublishP95: 100 * time.Millisecond, MaxNoisyInflation: 2},
			Comment: "pooled many-tenant, thousands of agents",
		},
		{
			Tier: TierXL,
			Ingest: IngestConfig{
				Tenants: 64, AgentsPerTenant: s(300), TestsPerAgent: 5,
				ResultsPerTest: s(30), Producers: 32, SettleTimeout: 10 * time.Minute,
			},
			SLO:     ScaleSLO{MinIngestThroughput: 25000, MaxPublishP95: 200 * time.Millisecond, MaxNoisyInflation: 2},
			Comment: "MSP-scale pooled mix, tens of thousands of agents",
		},
	}
}

// ProfileFor returns one tier's profile.
func ProfileFor(tier Tier, scale float64) (Profile, error) {
	for _, p := range Profiles(scale) {
		if p.Tier == tier {
			return p, nil
		}
	}
	return Profile{}, fmt.Errorf("perf: unknown tier %q", tier)
}

// ScaleReport is one gate run's outcome.
type ScaleReport struct {
	Profile    Profile
	Ingest     IngestReport
	Noisy      NoisyReport
	AtCIScale  bool
	Violations []string // empty = the gate passes
}

// noisyMaterialityFloor: the inflation RATIO only gates when the quiet
// tenant's under-noise p95 is itself material. A 2µs → 200µs swing is a
// 100x "inflation" of nothing — the experience is still excellent; ratios
// of microseconds are scheduler noise, not a noisy-neighbor problem.
const noisyMaterialityFloor = 5 * time.Millisecond

// evaluate applies the tier SLO. At CI scale the absolute throughput floors
// don't apply (CI hardware proves the gate, not the platform) — correctness
// always does, and the noisy-neighbor INFLATION ratio applies above the
// materiality floor (ratios survive scaling; noise does not).
func (r *ScaleReport) evaluate() {
	slo := r.Profile.SLO
	if !r.AtCIScale {
		if slo.MinIngestThroughput > 0 && r.Ingest.Throughput < slo.MinIngestThroughput {
			r.Violations = append(r.Violations, fmt.Sprintf(
				"%s: ingest throughput %.0f/s below the %.0f/s floor (PROVISIONAL SLO)",
				r.Profile.Tier, r.Ingest.Throughput, slo.MinIngestThroughput))
		}
		if slo.MaxPublishP95 > 0 && r.Ingest.PublishLatency.P95 > slo.MaxPublishP95 {
			r.Violations = append(r.Violations, fmt.Sprintf(
				"%s: publish p95 %s above the %s ceiling (PROVISIONAL SLO)",
				r.Profile.Tier, r.Ingest.PublishLatency.P95, slo.MaxPublishP95))
		}
	}
	if slo.MaxNoisyInflation > 0 && r.Noisy.Ran {
		if !r.Noisy.QuietCorrect {
			r.Violations = append(r.Violations, fmt.Sprintf(
				"%s: NOISY-NEIGHBOR CORRECTNESS BROKEN — the quiet tenant saw wrong results under load (F57)",
				r.Profile.Tier))
		}
		if r.Noisy.Inflation > slo.MaxNoisyInflation && r.Noisy.NoisyP95 >= noisyMaterialityFloor {
			r.Violations = append(r.Violations, fmt.Sprintf(
				"%s: noisy-neighbor p95 inflation %.2fx (at %s) above the %.1fx ceiling (F57; PROVISIONAL SLO)",
				r.Profile.Tier, r.Noisy.Inflation, r.Noisy.NoisyP95, slo.MaxNoisyInflation))
		}
	}
}

// RunScaleGate drives one tier end to end on the lightweight in-process
// stack: the ingest profile, then the noisy-neighbor scenario (multi-tenant
// tiers only). The same gate runs at CI scale (proving the gate) and full
// scale (proving the platform on reference hardware).
func RunScaleGate(ctx context.Context, tier Tier, scale float64) (ScaleReport, error) {
	profile, err := ProfileFor(tier, scale)
	if err != nil {
		return ScaleReport{}, err
	}
	rep := ScaleReport{Profile: profile, AtCIScale: scale < 1}

	b := bus.NewMemory()
	defer b.Close()
	w := tsdb.NewMemory()
	rep.Ingest, err = DriveIngest(ctx, b, w, w.Len, profile.Ingest)
	if err != nil {
		return rep, fmt.Errorf("perf: %s ingest: %w", tier, err)
	}

	if profile.Ingest.Tenants > 1 {
		rep.Noisy, err = DriveNoisyNeighbor(ctx, NoisyConfig{
			QuietResults: clampInt(profile.Ingest.TotalResults()/profile.Ingest.Tenants, 200, 5000),
			NoisyFactor:  10,
			Producers:    profile.Ingest.Producers,
		})
		if err != nil {
			return rep, fmt.Errorf("perf: %s noisy-neighbor: %w", tier, err)
		}
	}

	rep.evaluate()
	return rep, nil
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
