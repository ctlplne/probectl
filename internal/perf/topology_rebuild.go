// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package perf

import (
	"fmt"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/topology"
)

const (
	topologyRebuildEdgesPerAgent = 10
	topologyRebuildCISamples     = 3

	topologyRebuildCIAggregationRule = "median of 3 timing samples; correctness required in all samples"

	topologyRebuildTierLReplayP95 = 2 * time.Second
	topologyRebuildTierLTotal     = 10 * time.Second
)

// TopologyRebuildTarget is the cold-start replay target for one tier. Replay
// p95 is measured per tenant: after a restart, each tenant's graph should refill
// quickly as its own stream observations arrive, without another tenant's load
// changing the correctness result.
type TopologyRebuildTarget struct {
	Tier              Tier
	Tenants           int
	AgentsPerTenant   int
	EdgesPerAgent     int
	MaxReplayP95      time.Duration
	MaxSnapshotP95    time.Duration
	MaxTotal          time.Duration
	ManualXLAndBeyond bool
}

// Observations returns how many service-edge observations the fixture replays.
func (t TopologyRebuildTarget) Observations() int {
	return t.Tenants * t.AgentsPerTenant * t.EdgesPerAgent
}

// TopologyRebuildTargets returns the by-tier numeric cold-start targets. S/M/L
// run in CI; XL/XXL use the same driver as manual/reference receipts because
// they intentionally replay hundreds of thousands to one million observations.
func TopologyRebuildTargets() []TopologyRebuildTarget {
	return []TopologyRebuildTarget{
		{Tier: TierS, Tenants: 1, AgentsPerTenant: 25, EdgesPerAgent: topologyRebuildEdgesPerAgent, MaxReplayP95: 250 * time.Millisecond, MaxSnapshotP95: 75 * time.Millisecond, MaxTotal: time.Second},
		{Tier: TierM, Tenants: 8, AgentsPerTenant: 40, EdgesPerAgent: topologyRebuildEdgesPerAgent, MaxReplayP95: 500 * time.Millisecond, MaxSnapshotP95: 100 * time.Millisecond, MaxTotal: 3 * time.Second},
		{Tier: TierL, Tenants: 32, AgentsPerTenant: 100, EdgesPerAgent: topologyRebuildEdgesPerAgent, MaxReplayP95: topologyRebuildTierLReplayP95, MaxSnapshotP95: 250 * time.Millisecond, MaxTotal: topologyRebuildTierLTotal},
		{Tier: TierXL, Tenants: 64, AgentsPerTenant: 300, EdgesPerAgent: topologyRebuildEdgesPerAgent, MaxReplayP95: 5 * time.Second, MaxSnapshotP95: 500 * time.Millisecond, MaxTotal: 30 * time.Second, ManualXLAndBeyond: true},
		{Tier: TierXXL, Tenants: 100, AgentsPerTenant: 1000, EdgesPerAgent: topologyRebuildEdgesPerAgent, MaxReplayP95: 10 * time.Second, MaxSnapshotP95: time.Second, MaxTotal: 2 * time.Minute, ManualXLAndBeyond: true},
	}
}

// TopologyRebuildTargetFor returns one tier's cold-start target.
func TopologyRebuildTargetFor(tier Tier) (TopologyRebuildTarget, error) {
	for _, target := range TopologyRebuildTargets() {
		if target.Tier == tier {
			return target, nil
		}
	}
	return TopologyRebuildTarget{}, fmt.Errorf("perf: unknown topology rebuild tier %q", tier)
}

// TopologyRebuildReport is one replay/rebuild receipt.
type TopologyRebuildReport struct {
	Target          TopologyRebuildTarget
	Observations    int
	Nodes           int
	Edges           int
	Elapsed         time.Duration
	ReplayLatency   LatencyStat
	SnapshotLatency LatencyStat
	// CorrectnessViolations stay separate so the CI timing aggregator can
	// tolerate one scheduler-stalled sample without ever tolerating a missing,
	// mixed, or ghost tenant graph.
	CorrectnessViolations []string
	Violations            []string
}

// String renders the receipt row logged by tests and benchmarks.
func (r TopologyRebuildReport) String() string {
	verdict := "PASS"
	if len(r.Violations) > 0 {
		verdict = "FAIL"
	}
	return fmt.Sprintf(
		"topology-rebuild %s: tenants=%d observations=%d replay_p95=%s snapshot_p95=%s total=%s nodes=%d edges=%d %s",
		r.Target.Tier, r.Target.Tenants, r.Observations, round(r.ReplayLatency.P95),
		round(r.SnapshotLatency.P95), round(r.Elapsed), r.Nodes, r.Edges, verdict)
}

// DriveTopologyRebuild replays a deterministic tier-shaped topology fixture
// into a fresh store, modeling the restart state from docs/adr/volatile-stores.md.
func DriveTopologyRebuild(target TopologyRebuildTarget) TopologyRebuildReport {
	if target.EdgesPerAgent <= 0 {
		target.EdgesPerAgent = topologyRebuildEdgesPerAgent
	}
	rep := TopologyRebuildReport{Target: target, Observations: target.Observations()}
	store := topology.NewIndexedStore()
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	var replayLat, snapshotLat Latencies
	startAll := time.Now()
	for tenantIdx := 0; tenantIdx < target.Tenants; tenantIdx++ {
		tenant := topologyRebuildTenant(target.Tier, tenantIdx)
		graph, err := store.ForTenant(tenant)
		if err != nil {
			rep.CorrectnessViolations = append(rep.CorrectnessViolations, err.Error())
			continue
		}
		start := time.Now()
		replayTenantTopology(graph, tenantIdx, target, at)
		replayLat.Record(time.Since(start))

		start = time.Now()
		snap := graph.Latest()
		snapshotLat.Record(time.Since(start))
		rep.Nodes += len(snap.Nodes)
		rep.Edges += len(snap.Edges)

		expectedEdges := target.AgentsPerTenant * target.EdgesPerAgent
		if len(snap.Edges) != expectedEdges {
			rep.CorrectnessViolations = append(rep.CorrectnessViolations, fmt.Sprintf(
				"%s tenant %s rebuilt %d edges, want %d", target.Tier, tenant, len(snap.Edges), expectedEdges))
		}
	}
	rep.Elapsed = time.Since(startAll)
	rep.ReplayLatency = replayLat.Summary()
	rep.SnapshotLatency = snapshotLat.Summary()

	if ghost := store.Latest("never-seen"); len(ghost.Nodes) != 0 || len(ghost.Edges) != 0 {
		rep.CorrectnessViolations = append(rep.CorrectnessViolations, "cold-start ghost tenant was not empty")
	}
	rep.Violations = append(rep.Violations, rep.CorrectnessViolations...)
	rep.Violations = append(rep.Violations, topologyRebuildTimingViolations(
		target, rep.ReplayLatency.P95, rep.SnapshotLatency.P95, rep.Elapsed)...)
	return rep
}

type topologyRebuildGateReport struct {
	Target            TopologyRebuildTarget
	Samples           []TopologyRebuildReport
	MedianReplayP95   time.Duration
	MedianSnapshotP95 time.Duration
	MedianTotal       time.Duration
	Violations        []string
}

func (r topologyRebuildGateReport) String() string {
	verdict := "PASS"
	if len(r.Violations) > 0 {
		verdict = "FAIL"
	}
	raw := make([]string, 0, len(r.Samples))
	for idx, sample := range r.Samples {
		raw = append(raw, fmt.Sprintf(
			"#%d{replay_p95=%s snapshot_p95=%s total=%s correctness_violations=%d}",
			idx+1, sample.ReplayLatency.P95, sample.SnapshotLatency.P95, sample.Elapsed,
			len(sample.CorrectnessViolations)))
	}
	return fmt.Sprintf(
		"topology-rebuild-gate %s: rule=%q samples=[%s] median={replay_p95=%s snapshot_p95=%s total=%s} %s",
		r.Target.Tier, topologyRebuildCIAggregationRule, strings.Join(raw, " "),
		r.MedianReplayP95, r.MedianSnapshotP95, r.MedianTotal, verdict)
}

// driveTopologyRebuildCIGate repeats the deterministic fixture and uses the
// median timing sample for CI. One host scheduling pause can poison at most one
// of three samples, while a sustained regression poisons the median. Correctness
// remains fail-closed: every sample must rebuild every tenant exactly.
func driveTopologyRebuildCIGate(target TopologyRebuildTarget) topologyRebuildGateReport {
	samples := make([]TopologyRebuildReport, 0, topologyRebuildCISamples)
	for range topologyRebuildCISamples {
		samples = append(samples, DriveTopologyRebuild(target))
	}
	return evaluateTopologyRebuildGate(target, samples)
}

func evaluateTopologyRebuildGate(target TopologyRebuildTarget, samples []TopologyRebuildReport) topologyRebuildGateReport {
	rep := topologyRebuildGateReport{Target: target, Samples: samples}
	if len(samples) != topologyRebuildCISamples {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s topology rebuild gate has %d samples, want %d",
			target.Tier, len(samples), topologyRebuildCISamples))
		return rep
	}

	var replay, snapshot, total Latencies
	for idx, sample := range samples {
		replay.Record(sample.ReplayLatency.P95)
		snapshot.Record(sample.SnapshotLatency.P95)
		total.Record(sample.Elapsed)
		for _, violation := range sample.CorrectnessViolations {
			rep.Violations = append(rep.Violations, fmt.Sprintf(
				"%s sample %d correctness: %s", target.Tier, idx+1, violation))
		}
	}
	rep.MedianReplayP95 = replay.Summary().P50
	rep.MedianSnapshotP95 = snapshot.Summary().P50
	rep.MedianTotal = total.Summary().P50
	for _, violation := range topologyRebuildTimingViolations(
		target, rep.MedianReplayP95, rep.MedianSnapshotP95, rep.MedianTotal) {
		rep.Violations = append(rep.Violations, "median-of-3 "+violation)
	}
	return rep
}

func topologyRebuildTimingViolations(
	target TopologyRebuildTarget,
	replayP95, snapshotP95, total time.Duration,
) []string {
	var violations []string
	if replayP95 > target.MaxReplayP95 {
		violations = append(violations, fmt.Sprintf(
			"%s replay p95 %s above %s", target.Tier, replayP95, target.MaxReplayP95))
	}
	if snapshotP95 > target.MaxSnapshotP95 {
		violations = append(violations, fmt.Sprintf(
			"%s snapshot p95 %s above %s", target.Tier, snapshotP95, target.MaxSnapshotP95))
	}
	if total > target.MaxTotal {
		violations = append(violations, fmt.Sprintf(
			"%s total rebuild %s above %s", target.Tier, total, target.MaxTotal))
	}
	return violations
}

func replayTenantTopology(graph topology.TenantStore, tenantIdx int, target TopologyRebuildTarget, at time.Time) {
	for agent := 0; agent < target.AgentsPerTenant; agent++ {
		for edge := 0; edge < target.EdgesPerAgent; edge++ {
			graph.ObserveServiceEdge(topology.ServiceEdgeInput{
				Source:      fmt.Sprintf("tenant-%03d-agent-%04d-workload-%02d", tenantIdx, agent, edge),
				Destination: fmt.Sprintf("tenant-%03d-backend-%02d", tenantIdx, edge),
				DestPort:    uint32(8000 + edge%100),
				Transport:   "tcp",
				Protocol:    "http",
			}, at.Add(time.Duration(agent*target.EdgesPerAgent+edge)*time.Millisecond))
		}
	}
}

func topologyRebuildTenant(tier Tier, idx int) string {
	return fmt.Sprintf("topology-%s-tenant-%03d", strings.ToLower(string(tier)), idx)
}
