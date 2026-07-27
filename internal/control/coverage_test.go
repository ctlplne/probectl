// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"net/http"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/topology"
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

	items := buildCoverageMatrix(candidates, latest.List("tenant-a"), now)
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
