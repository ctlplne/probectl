// SPDX-License-Identifier: LicenseRef-probectl-TBD

package perf

import (
	"fmt"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/topology"
)

const (
	topologyRebuildEdgesPerAgent = 10

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
	Violations      []string
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
			rep.Violations = append(rep.Violations, err.Error())
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
			rep.Violations = append(rep.Violations, fmt.Sprintf(
				"%s tenant %s rebuilt %d edges, want %d", target.Tier, tenant, len(snap.Edges), expectedEdges))
		}
	}
	rep.Elapsed = time.Since(startAll)
	rep.ReplayLatency = replayLat.Summary()
	rep.SnapshotLatency = snapshotLat.Summary()

	if ghost := store.Latest("never-seen"); len(ghost.Nodes) != 0 || len(ghost.Edges) != 0 {
		rep.Violations = append(rep.Violations, "cold-start ghost tenant was not empty")
	}
	if rep.ReplayLatency.P95 > target.MaxReplayP95 {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s replay p95 %s above %s", target.Tier, rep.ReplayLatency.P95, target.MaxReplayP95))
	}
	if rep.SnapshotLatency.P95 > target.MaxSnapshotP95 {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s snapshot p95 %s above %s", target.Tier, rep.SnapshotLatency.P95, target.MaxSnapshotP95))
	}
	if rep.Elapsed > target.MaxTotal {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s total rebuild %s above %s", target.Tier, rep.Elapsed, target.MaxTotal))
	}
	return rep
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
