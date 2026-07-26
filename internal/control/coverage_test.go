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
