// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/topology"
)

func TestBuildCoverageMatrixStatesAndTenantResultPartition(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	seen := now.Add(-time.Minute)
	candidates := []store.CoverageCandidate{
		{TestID: "uncovered", TestName: "no-vantage", ProbeFamily: "icmp", Target: "uncovered.example", IntervalSeconds: 60, Region: "unlabeled", Site: "unlabeled"},
		{TestID: "stale", TestName: "old", ProbeFamily: "dns", Target: "stale.example", IntervalSeconds: 60, AgentID: "a1", Region: "eu", Site: "dub", AgentStatus: "online", LastSeenAt: &seen},
		{TestID: "single", TestName: "single", ProbeFamily: "tcp", Target: "single.example:443", IntervalSeconds: 60, AgentID: "a1", Region: "eu", Site: "dub", AgentStatus: "online", LastSeenAt: &seen},
		{TestID: "covered", TestName: "covered", ProbeFamily: "http", Target: "https://covered.example", IntervalSeconds: 60, AgentID: "a1", Region: "us", Site: "iad", AgentStatus: "online", LastSeenAt: &seen},
		{TestID: "covered", TestName: "covered", ProbeFamily: "http", Target: "https://covered.example", IntervalSeconds: 60, AgentID: "a2", Region: "us", Site: "iad", AgentStatus: "online", LastSeenAt: &seen},
	}

	latest := NewLatestResults(20)
	latest.Record("tenant-a", ResultView{AgentID: "a1", Type: "dns", Target: "stale.example", ObservedAt: now.Add(-20 * time.Minute)})
	latest.Record("tenant-a", ResultView{AgentID: "a1", Type: "tcp", Target: "single.example:443", ObservedAt: now.Add(-time.Minute)})
	latest.Record("tenant-a", ResultView{AgentID: "a1", Type: "http", Target: "https://covered.example", ObservedAt: now.Add(-time.Minute)})
	latest.Record("tenant-a", ResultView{AgentID: "a2", Type: "http", Target: "https://covered.example", ObservedAt: now.Add(-2 * time.Minute)})
	// Same series but a distinguishable future timestamp in another tenant.
	// Building from tenant-a's partition must never observe it.
	latest.Record("tenant-b", ResultView{AgentID: "a1", Type: "tcp", Target: "single.example:443", ObservedAt: now.Add(time.Hour)})

	recent, evictedThrough := latest.RecentSnapshot("tenant-a")
	items := buildCoverageMatrix(
		candidates,
		latest.List("tenant-a"),
		recent,
		evictedThrough,
		true,
		now,
	)
	byID := map[string]coverageMatrixItem{}
	for _, item := range items {
		byID[item.TestID] = item
	}
	if got := byID["uncovered"]; got.Status != "uncovered" || got.IndependentVantageCount != 0 {
		t.Fatalf("uncovered = %+v", got)
	}
	if got := byID["stale"]; got.Status != "stale" || got.LastEvidenceAt == nil {
		t.Fatalf("stale = %+v", got)
	}
	if got := byID["single"]; got.Status != "non_redundant" ||
		got.IndependentVantageCount != 1 || got.LastEvidenceAt == nil || got.LastEvidenceAt.After(now) {
		t.Fatalf("single = %+v (other tenant recency leaked?)", got)
	}
	if got := byID["covered"]; got.Status != "covered" || got.IndependentVantageCount != 2 || got.NextAction != nil {
		t.Fatalf("covered = %+v", got)
	}
}

func TestExecutionCadenceReceiptIsExactDeduplicatedAndTwoTenantScoped(t *testing.T) {
	now := time.Date(2026, 7, 28, 6, 0, 0, 0, time.UTC)
	candidates := []store.CoverageCandidate{{
		TestID: "test-cadence", TestName: "edge-dns", ProbeFamily: "dns",
		Target: "example.test", IntervalSeconds: 30, AgentID: "agent-a",
		Region: "eu", Site: "dub", AgentStatus: "online",
		LastSeenAt: timePointer(now.Add(-time.Minute)),
	}}
	attributes := map[string]string{
		"probectl.test.id":               "test-cadence",
		"probectl.test.interval_seconds": "30",
	}
	latest := NewLatestResults(20)
	latest.recentStartedAt = now.Add(-cadenceMinimumWindow - time.Second)
	for i, age := range []time.Duration{90 * time.Second, 60 * time.Second, 30 * time.Second, 0} {
		latest.Record("tenant-a", ResultView{
			ResultID: "result-" + string(rune('a'+i)), AgentID: "agent-a",
			Type: "dns", Target: "example.test", Attributes: attributes,
			ObservedAt: now.Add(-age),
		})
	}
	// At-least-once redelivery must not manufacture an extra observed round.
	latest.Record("tenant-a", ResultView{
		ResultID: "result-d", AgentID: "agent-a", Type: "dns", Target: "example.test",
		Attributes: attributes, ObservedAt: now,
	})
	// Same exact test id in another tenant has a future timestamp and interval
	// mismatch. Neither fact may influence tenant A's receipt.
	latest.Record("tenant-b", ResultView{
		ResultID: "secret", AgentID: "agent-a", Type: "dns", Target: "example.test",
		Attributes: map[string]string{
			"probectl.test.id":               "test-cadence",
			"probectl.test.interval_seconds": "300",
		},
		ObservedAt: now.Add(time.Hour),
	})

	recent, evictedThrough := latest.RecentSnapshot("tenant-a")
	items := buildCoverageMatrix(
		candidates, latest.List("tenant-a"), recent, evictedThrough, true, now,
	)
	if len(items) != 1 {
		t.Fatalf("items = %+v", items)
	}
	got := items[0].ExecutionCadence
	if got.State != "on_cadence" || got.Reason != "on_cadence" ||
		got.Attribution != "exact_test_id" || got.ObservedRounds != 4 ||
		got.ExpectedRounds != 4 || got.MissedRounds != 0 ||
		got.ObservedAgentCount != 1 || !got.HistoryComplete ||
		got.CurrentAssignmentVerified {
		t.Fatalf("tenant A cadence = %+v", got)
	}
}

func TestExecutionCadenceReceiptHonestyStates(t *testing.T) {
	now := time.Date(2026, 7, 28, 6, 0, 0, 0, time.UTC)
	agents := map[string]struct{}{"agent-a": {}}
	result := func(id string, at time.Time, interval string) ResultView {
		return ResultView{
			ResultID: id, AgentID: "agent-a", Type: "dns", Target: "example.test",
			ObservedAt: at,
			Attributes: map[string]string{
				"probectl.test.id":               "test-cadence",
				"probectl.test.interval_seconds": interval,
			},
		}
	}
	for name, tc := range map[string]struct {
		recent  []ResultView
		evicted time.Time
		running bool
		state   string
		reason  string
		missed  int
	}{
		"unwired": {
			running: false, state: "unknown", reason: "evidence_unwired",
		},
		"never observed": {
			running: true, state: "never_observed", reason: "no_exact_test_evidence",
		},
		"restart window incomplete": {
			running: true, evicted: now,
			state: "unknown", reason: "history_truncated",
		},
		"legacy attribution": {
			running: true,
			recent: []ResultView{{
				AgentID: "agent-a", Type: "dns", Target: "example.test",
				ObservedAt: now.Add(-time.Minute),
			}},
			state: "unknown", reason: "legacy_or_unattributed_evidence",
		},
		"interval mismatch": {
			running: true,
			recent:  []ResultView{result("mismatch", now.Add(-time.Minute), "60")},
			state:   "unknown", reason: "interval_mismatch",
		},
		"incomplete ring": {
			running: true,
			recent: []ResultView{
				result("one", now.Add(-30*time.Second), "30"),
				result("two", now, "30"),
			},
			evicted: now.Add(-time.Minute),
			state:   "unknown", reason: "history_truncated",
		},
		"positive gap evidence": {
			running: true,
			recent: []ResultView{
				result("one", now.Add(-90*time.Second), "30"),
				result("two", now.Add(-30*time.Second), "30"),
				result("three", now, "30"),
			},
			state: "gaps_observed", reason: "missed_rounds", missed: 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := buildExecutionCadence(
				"test-cadence", "dns", "example.test", 30, agents,
				tc.recent, tc.evicted, tc.running, now,
			)
			if got.State != tc.state || got.Reason != tc.reason || got.MissedRounds != tc.missed {
				t.Fatalf("receipt = %+v, want state=%s reason=%s missed=%d", got, tc.state, tc.reason, tc.missed)
			}
			if got.CurrentAssignmentVerified {
				t.Fatal("local YAML assignment must never be claimed as currently verified")
			}
		})
	}
}

func TestExecutionCadenceReceiptIgnoresOnlyObsoletePreWindowMetadata(t *testing.T) {
	now := time.Date(2026, 7, 28, 7, 0, 0, 0, time.UTC)
	agents := map[string]struct{}{"agent-a": {}}
	result := func(id string, at time.Time, interval string) ResultView {
		return ResultView{
			ResultID: id, AgentID: "agent-a", Type: "dns", Target: "example.test",
			ObservedAt: at,
			Attributes: map[string]string{
				"probectl.test.id":               "test-cadence",
				"probectl.test.interval_seconds": interval,
			},
		}
	}
	window := 6 * time.Minute
	healthyWindow := []ResultView{
		result("obsolete-missing", now.Add(-30*time.Minute), ""),
		result("obsolete-mismatch", now.Add(-20*time.Minute), "300"),
		result("nearest-valid-boundary", now.Add(-window-30*time.Second), "60"),
	}
	for i, age := range []time.Duration{
		5*time.Minute + 30*time.Second,
		4*time.Minute + 30*time.Second,
		3*time.Minute + 30*time.Second,
		2*time.Minute + 30*time.Second,
		time.Minute + 30*time.Second,
		30 * time.Second,
	} {
		healthyWindow = append(healthyWindow, result(
			"current-"+string(rune('a'+i)),
			now.Add(-age),
			"60",
		))
	}
	got := buildExecutionCadence(
		"test-cadence", "dns", "example.test", 60, agents,
		healthyWindow, time.Time{}, true, now,
	)
	if got.State != "on_cadence" || got.Reason != "on_cadence" ||
		got.ObservedRounds != 6 || got.MissedRounds != 0 {
		t.Fatalf("obsolete metadata poisoned current window: %+v", got)
	}

	relevantMismatch := append([]ResultView(nil), healthyWindow[3:]...)
	relevantMismatch = append(relevantMismatch,
		result("nearest-mismatch-boundary", now.Add(-window-30*time.Second), "300"))
	got = buildExecutionCadence(
		"test-cadence", "dns", "example.test", 60, agents,
		relevantMismatch, time.Time{}, true, now,
	)
	if got.State != "unknown" || got.Reason != "interval_mismatch" {
		t.Fatalf("nearest boundary mismatch was ignored: %+v", got)
	}
}

func timePointer(v time.Time) *time.Time { return &v }

func TestCoverageRouteIsReadOnlyAndPermissioned(t *testing.T) {
	for _, route := range testServer(fakePinger{}).apiRoutes() {
		if route.Pattern != "/v1/coverage/vantages" {
			continue
		}
		if route.Method != http.MethodGet || route.Permission != permTestRead {
			t.Fatalf("coverage route = %s %s %s", route.Method, route.Pattern, route.Permission)
		}
		return
	}
	t.Fatal("/v1/coverage/vantages not registered")
}

func TestBuildCoverageDebtRequiresExactPlaneEvidence(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Minute)
	old := now.Add(-time.Hour)
	candidates := []store.CoverageCandidate{
		{
			TestID: "test-fresh", TestName: "fresh", ProbeFamily: "tcp",
			Target: "api.example:443", IntervalSeconds: 60, AgentID: "agent-a",
			Region: "us-east", Site: "iad-1",
		},
		{
			TestID: "test-missing", TestName: "missing", ProbeFamily: "dns",
			Target: "dns.example", IntervalSeconds: 60, AgentID: "agent-b",
			Region: "eu-west", Site: "dub-1",
		},
		{
			TestID: "test-future", TestName: "future", ProbeFamily: "http",
			Target: "https://future.example", IntervalSeconds: 60, AgentID: "agent-c",
			Region: "ap-south", Site: "bom-1",
		},
	}
	results := []ResultView{
		{AgentID: "agent-a", Type: "tcp", Target: "api.example:443", ObservedAt: fresh},
		{
			AgentID: "agent-c", Type: "http", Target: "https://future.example",
			ObservedAt: now.Add(time.Hour),
		},
	}
	snapshot := topology.Snapshot{
		Tenant: "tenant-a", At: fresh,
		Nodes: []topology.Node{
			{ID: "service:api", Kind: topology.NodeService, Label: "api", LastSeen: fresh},
			{ID: "service:orphan", Kind: topology.NodeService, Label: "orphan", LastSeen: fresh},
			{ID: "prefix:203.0.113.0/24", Kind: topology.NodePrefix, Label: "203.0.113.0/24", LastSeen: old},
			{ID: "hop:10.0.0.1", Kind: topology.NodeHop, Label: "10.0.0.1", LastSeen: fresh},
		},
		Edges: []topology.Edge{{
			ID:   "hop:10.0.0.1|path|host:203.0.113.10",
			From: "hop:10.0.0.1", To: "host:203.0.113.10",
			Kind: topology.EdgePath, LastSeen: fresh,
		}, {
			ID: "service:api|flow|service:db", From: "service:api", To: "service:db",
			Kind: topology.EdgeFlow, LastSeen: fresh,
		}, {
			ID:   "as:64500|routing|prefix:203.0.113.0/24",
			From: "as:64500", To: "prefix:203.0.113.0/24",
			Kind: topology.EdgeRouting, LastSeen: old,
		}},
	}

	built := buildCoverageDebt(candidates, results, snapshot, coverageDebtBuildOptions{
		now: now, evidenceRunning: true, topologyRunning: true, entityLimit: 20,
	})
	find := func(entityID, plane string) coverageDebtItem {
		t.Helper()
		for _, item := range built.items {
			if item.EntityID == entityID && item.Plane == plane {
				return item
			}
		}
		t.Fatalf("missing %s/%s row", entityID, plane)
		return coverageDebtItem{}
	}

	if got := find("site:us-east:iad-1", "synthetic"); got.State != "covered" ||
		got.EvidenceBasis != "latest_test_result" || got.ObservedAt == nil {
		t.Fatalf("fresh site evidence = %+v", got)
	}
	if got := find("site:eu-west:dub-1", "synthetic"); got.State != "uncovered" ||
		got.EvidenceBasis != "no_persisted_test_result" {
		t.Fatalf("registration without evidence must not be green: %+v", got)
	}
	if got := find("site:ap-south:bom-1", "synthetic"); got.State != "unknown" ||
		got.EvidenceBasis != "future_evidence_timestamp" {
		t.Fatalf("future evidence must expose clock uncertainty: %+v", got)
	}
	if got := find("service:api", "flow"); got.State != "covered" ||
		got.EvidenceBasis != "topology_flow_edge" {
		t.Fatalf("service flow evidence = %+v", got)
	}
	if got := find("service:api", "routing"); got.State != "unknown" ||
		got.EvidenceBasis != "no_exact_entity_correlation" {
		t.Fatalf("uncorrelated service routing state must be unknown: %+v", got)
	}
	if got := find("service:orphan", "flow"); got.State != "uncovered" ||
		got.EvidenceBasis != "no_persisted_topology_edge" {
		t.Fatalf("typed topology existence without an edge must not be green: %+v", got)
	}
	if got := find("prefix:203.0.113.0/24", "routing"); got.State != "stale" ||
		got.EvidenceAgeSeconds == nil || *got.EvidenceAgeSeconds != 3600 {
		t.Fatalf("stale routing evidence = %+v", got)
	}
	if got := find("hop:10.0.0.1", "path"); got.State != "covered" ||
		got.EvidenceBasis != "topology_path_edge" {
		t.Fatalf("hop must use exact incident edge evidence: %+v", got)
	}
	if got := find("hop:10.0.0.1", "device"); got.State != "unknown" {
		t.Fatalf("hop without device edge must not infer device coverage: %+v", got)
	}
}

func TestBuildCoverageDebtDoesNotCrossDuplicateTestIdentity(t *testing.T) {
	now := time.Date(2026, 8, 23, 2, 0, 0, 0, time.UTC)
	candidates := []store.CoverageCandidate{
		{TestID: "test-old", TestName: "old", ProbeFamily: "icmp", Target: "127.0.0.1", IntervalSeconds: 15, AgentID: "agent-a", Region: "local", Site: "lab"},
		{TestID: "test-new", TestName: "new", ProbeFamily: "icmp", Target: "127.0.0.1", IntervalSeconds: 15, AgentID: "agent-a", Region: "local", Site: "lab"},
	}
	results := []ResultView{{
		AgentID: "agent-a", Type: "icmp", Target: "127.0.0.1", ObservedAt: now,
		Attributes: map[string]string{"probectl.test.id": "test-new"},
	}}

	built := buildCoverageDebt(candidates, results, topology.Snapshot{}, coverageDebtBuildOptions{
		now: now, evidenceRunning: true, topologyRunning: true, entityLimit: 20,
	})
	for _, item := range built.items {
		if item.EntityID == "site:local:lab" && item.Plane == "synthetic" {
			if item.State != "covered" || item.EvidenceRef != "test-new/agent-a" {
				t.Fatalf("duplicate-test evidence crossed identity: %+v", item)
			}
			return
		}
	}
	t.Fatal("missing synthetic coverage-debt row")
}

func TestBuildCoverageDebtRejectsAmbiguousLegacyDuplicateEvidence(t *testing.T) {
	now := time.Date(2026, 8, 23, 2, 0, 0, 0, time.UTC)
	candidates := []store.CoverageCandidate{
		{TestID: "test-a", ProbeFamily: "icmp", Target: "127.0.0.1", AgentID: "agent-a", Region: "local", Site: "lab"},
		{TestID: "test-b", ProbeFamily: "icmp", Target: "127.0.0.1", AgentID: "agent-a", Region: "local", Site: "lab"},
	}
	results := []ResultView{{AgentID: "agent-a", Type: "icmp", Target: "127.0.0.1", ObservedAt: now}}

	built := buildCoverageDebt(candidates, results, topology.Snapshot{}, coverageDebtBuildOptions{
		now: now, evidenceRunning: true, topologyRunning: true, entityLimit: 20,
	})
	for _, item := range built.items {
		if item.EntityID == "site:local:lab" && item.Plane == "synthetic" {
			if item.State != "uncovered" || item.EvidenceBasis != "no_persisted_test_result" {
				t.Fatalf("ambiguous legacy evidence must fail closed: %+v", item)
			}
			return
		}
	}
	t.Fatal("missing synthetic coverage-debt row")
}

func TestBuildCoverageDebtMakesIncompleteAbsenceUnknown(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	candidates := []store.CoverageCandidate{{
		TestID: "test", TestName: "test", ProbeFamily: "tcp", Target: "api:443",
		IntervalSeconds: 60, AgentID: "agent", Region: "us", Site: "iad",
	}}
	for _, tc := range []struct {
		name             string
		evidenceRunning  bool
		truncated        bool
		resultsTruncated bool
		wantBasis        string
	}{
		{name: "unwired producer", wantBasis: "producer_unwired"},
		{
			name: "truncated candidate scan", evidenceRunning: true, truncated: true,
			wantBasis: "candidate_scan_truncated",
		},
		{
			name: "truncated result evidence", evidenceRunning: true, resultsTruncated: true,
			wantBasis: "result_evidence_truncated",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			built := buildCoverageDebt(candidates, nil, topology.Snapshot{}, coverageDebtBuildOptions{
				now: now, evidenceRunning: tc.evidenceRunning, topologyRunning: true,
				candidatesTruncated: tc.truncated, resultsTruncated: tc.resultsTruncated,
				entityLimit: 10,
			})
			for _, item := range built.items {
				if item.EntityKind == "site" && item.Plane == "synthetic" {
					if item.State != "unknown" || item.EvidenceBasis != tc.wantBasis {
						t.Fatalf("item = %+v", item)
					}
					return
				}
			}
			t.Fatal("missing site/synthetic row")
		})
	}
}

func TestBuildCoverageDebtIsBoundedAndReportsTopologyTruncation(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	nodes := make([]topology.Node, 0, 4)
	for _, id := range []string{"service:a", "service:b", "service:c", "service:d"} {
		nodes = append(nodes, topology.Node{
			ID: id, Kind: topology.NodeService, Label: id, LastSeen: now,
		})
	}
	built := buildCoverageDebt(nil, nil, topology.Snapshot{Nodes: nodes}, coverageDebtBuildOptions{
		now: now, evidenceRunning: true, topologyRunning: true, entityLimit: 2,
	})
	if len(built.items) != 2*coverageDebtPlaneCount {
		t.Fatalf("items = %d, want two entities × five planes", len(built.items))
	}
	if !built.entitiesTruncated || !built.topologyTruncated {
		t.Fatalf("truncation = entities:%v topology:%v", built.entitiesTruncated, built.topologyTruncated)
	}
}

func TestCoverageDebtRouteIsReadOnlyAndPermissioned(t *testing.T) {
	for _, route := range testServer(fakePinger{}).apiRoutes() {
		if route.Pattern != "/v1/coverage/debt" {
			continue
		}
		if route.Method != http.MethodGet || route.Permission != permTestRead {
			t.Fatalf("coverage debt route = %s %s %s", route.Method, route.Pattern, route.Permission)
		}
		return
	}
	t.Fatal("/v1/coverage/debt not registered")
}
