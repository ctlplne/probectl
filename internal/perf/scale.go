// SPDX-License-Identifier: LicenseRef-probectl-TBD

package perf

// The S48 L/XL/XXL scale gate: the S/M/L/XL/XXL reference-architecture load profiles
// (PRD §5.4), the numeric SLOs they are validated against, and the
// multi-tenant NOISY-NEIGHBOR scenario (one tenant flooding must not bleed
// into another tenant's experience — F57, the M14 milestone line).
//
// ⚠ The numeric SLO targets are PROVISIONAL / UNVERIFIED (SCALE-004). CLAUDE.md
// §2 lists numeric SLO targets as a human-owned open decision: these values are
// engineering estimates recorded so the gate is runnable end to end. They become
// VERIFIED only when a full L/XL/XXL run on reference hardware is recorded in
// docs/scale-gate.md — that run is the separate EXC-GATE-01 epic, NOT this
// in-process gate. The in-process gate proves the gate's machinery (profiles
// drive, the per-tenant fairness gate SHEDS a flooding neighbor — a timing-
// independent isolation signal that runs on every CI pass and has a negative
// control — and correctness holds), not the platform's absolute numbers. Change
// the SLO numbers in docs/scale-gate.md and here together.
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
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// Tier names a PRD §5.4 reference architecture.
type Tier string

// The reference tiers (PRD §5.4).
const (
	TierS   Tier = "S"   // homelab/compose, single-tenant, ≤~25 agents
	TierM   Tier = "M"   // HA K8s, small pooled multi-tenant, hundreds of agents
	TierL   Tier = "L"   // sharded, pooled many-tenant, thousands of agents
	TierXL  Tier = "XL"  // MSP-scale pooled+siloed mix, tens of thousands of agents
	TierXXL Tier = "XXL" // 100k-agent provider fan-out envelope
)

// ScaleSLO is the numeric gate for one tier — PROVISIONAL / UNVERIFIED (see the
// package note): recorded so the gate runs, awaiting the EXC-GATE-01 reference-
// hardware run + human sign-off.
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
		{
			Tier: TierXXL,
			Ingest: IngestConfig{
				Tenants: 100, AgentsPerTenant: s(1000), TestsPerAgent: 5,
				ResultsPerTest: s(20), Producers: 64, SettleTimeout: 20 * time.Minute,
			},
			SLO:     ScaleSLO{MinIngestThroughput: 100000, MaxPublishP95: 250 * time.Millisecond, MaxNoisyInflation: 2},
			Comment: "100k-agent provider fan-out envelope",
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
//
// U-055: ONE floor, the documented 5ms, in CI and at full scale alike. CI
// previously carried a 6x-loosened floor (30ms) to absorb shared-runner
// jitter; that was a silent SLO weakening. The jitter is now absorbed
// structurally instead — DriveNoisyNeighbor measures temporally-adjacent
// (solo, noisy) pairs and gates on the MEDIAN of 3, so a transient host
// stall cannot fake (or hide) a noisy neighbor — and the documented floor
// applies everywhere (docs/scale-gate.md). Correctness (QuietCorrect)
// remains the hard backstop with no floor and no scale exemption.
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
		// SCALE-004: the TIMING-INDEPENDENT isolation assertion that ALWAYS runs
		// when a fairness gate is installed. On the in-memory stack latency is
		// microseconds, so the p95-inflation gate below is structurally blind
		// (NoisyP95 < the 5ms materiality floor); the gate's real job — shedding
		// a flooding tenant so it cannot starve the platform — is asserted here
		// regardless of timing. With the gate installed the flood MUST be shed
		// (admit fraction materially below 1); a fraction near 1 means the gate
		// is not wired (the audited gap) and is a hard violation.
		if r.Noisy.FairnessOn {
			if r.Noisy.NoisyPublished == 0 {
				r.Violations = append(r.Violations, fmt.Sprintf(
					"%s: noisy-neighbor harness published no flood — the scenario did not exercise the fairness gate (SCALE-004)",
					r.Profile.Tier))
			} else if r.Noisy.NoisyAdmitFrac > maxNoisyAdmitFrac {
				r.Violations = append(r.Violations, fmt.Sprintf(
					"%s: fairness gate did NOT shed the flooding neighbor — admitted %.0f%% of %d flood results (want <= %.0f%%); the noisy-neighbor gate is not actually installed (SCALE-004 / F57)",
					r.Profile.Tier, r.Noisy.NoisyAdmitFrac*100, r.Noisy.NoisyPublished, maxNoisyAdmitFrac*100))
			}
		}
		if r.Noisy.Inflation > slo.MaxNoisyInflation && r.Noisy.NoisyP95 >= noisyMaterialityFloor {
			r.Violations = append(r.Violations, fmt.Sprintf(
				"%s: noisy-neighbor p95 inflation %.2fx (at %s) above the %.1fx ceiling (F57; PROVISIONAL SLO)",
				r.Profile.Tier, r.Noisy.Inflation, r.Noisy.NoisyP95, slo.MaxNoisyInflation))
		}
	}
}

// maxNoisyAdmitFrac is the SCALE-004 timing-independent isolation ceiling: with
// the fairness gate installed, a flooding neighbor (10x the quiet workload) must
// have at most this fraction of its flood admitted — the rest is shed. A
// fraction above this means the gate is not actually bounding the flood. Set
// conservatively (0.95) so it fires on an UNINSTALLED gate (~1.0) without
// false-positiving on a gate that sheds even modestly.
const maxNoisyAdmitFrac = 0.95

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
		// SCALE-004: install the fairness gate the noisy-neighbor scenario is
		// supposed to validate. A flooding tenant is bounded so the in-process
		// gate has a TIMING-INDEPENDENT isolation signal (the in-memory bus has
		// microsecond latency — a p95-inflation gate alone is structurally
		// blind below the materiality floor). The quiet tenant's rate is
		// generous; the noisy tenant's flood far exceeds its bound, so it is shed.
		quietN := clampInt(profile.Ingest.TotalResults()/profile.Ingest.Tenants, 200, 5000)
		repeats := 3
		// Size the per-tenant bound so the quiet workload fits across every
		// phase the stateful gate sees: each pair runs solo then noisy, and the
		// same gate is reused across all median-deflake repeats. The quiet tenant
		// gets all 2*repeats phases plus one phase of headroom, while the 10x
		// noisy flood still blows through the bucket and must be shed.
		rate := float64(quietN * (2*repeats + 1))
		gate := fairness.NewGate(fairness.Policy{ResultsPerSec: rate, BurstSeconds: 1}, nil)
		rep.Noisy, err = DriveNoisyNeighbor(ctx, NoisyConfig{
			QuietResults:  quietN,
			NoisyFactor:   10,
			Producers:     profile.Ingest.Producers,
			SettleTimeout: 15 * time.Second, // bounded drain (shed flood drains fast)
			Repeats:       repeats,
			Fairness:      gate,
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
