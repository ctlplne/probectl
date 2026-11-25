// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
)

func TestRoutingProbeComparisonRequiresEveryPairedWitness(t *testing.T) {
	from := time.Date(2026, time.November, 24, 4, 0, 0, 0, time.UTC)
	scan := routingProbeScan{from: from, to: from.Add(time.Minute), interval: 30 * time.Second,
		slots: make([][2]routingTransferProbeSlot, 2)}
	scan.plan.target = netip.MustParseAddr("203.0.113.90")
	scan.plan.tests[0] = store.IncidentConfiguredTest{TenantID: "tenant-a", ContextID: "ctx", EntityID: "router", SourceGeneration: 7,
		TestID: "current-test", AgentID: "current-agent"}
	scan.plan.tests[1] = store.IncidentConfiguredTest{TenantID: "tenant-a", ContextID: "ctx", EntityID: "router", SourceGeneration: 7,
		TestID: "candidate-test", AgentID: "candidate-agent"}
	scan.plan.bindings[0].Egress = entity.ICMPEgressWitness{Interface: "eth0", Source: "192.0.2.7", PeerMAC: "02:01:02:03:04:05"}
	scan.plan.bindings[1].Egress = entity.ICMPEgressWitness{Interface: "eth0", Source: "198.51.100.7", PeerMAC: "02:01:02:03:04:06"}
	var candidateLast store.IncidentTestMeasurement
	for slot := range scan.slots {
		for lane := range scan.plan.tests {
			source := scan.plan.tests[lane]
			witness := scan.plan.bindings[lane].Egress
			witness.Transmitted = 2
			start := from.Add(time.Duration(slot)*scan.interval + time.Duration(lane+1)*time.Second)
			item := store.IncidentTestMeasurement{TenantID: source.TenantID, ContextID: source.ContextID, EntityID: source.EntityID,
				SourceGeneration: source.SourceGeneration, TestID: source.TestID, AgentID: source.AgentID,
				ObservationID: source.TestID + start.Format(time.RFC3339), CaptureDigest: [32]byte{byte(slot + 1), byte(lane + 1)},
				Alias: scan.plan.target.String(), Available: true, ICMP: &entity.ICMPMeasurement{
					Version: entity.ICMPVersionEgress, StartedAt: start, CompletedAt: start.Add(time.Second),
					Requested: 2, Attempted: 2, Transmitted: 2, ReadComplete: true, Egress: &witness,
					RoundTrips: &entity.ICMPRoundTrips{Nanos: []uint64{}}}}
			if lane == 1 {
				item.ICMP.Replies = 1
				item.ICMP.RoundTrips.Nanos = []uint64{uint64(15 + slot*5)}
				candidateLast = item
			}
			if err := scan.add(item); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !scan.complete() {
		t.Fatal("complete contemporaneous pairs did not qualify")
	}
	if source := scan.stats(0); source.Transmitted != 4 || source.Reachable || source.LossRatio != "1" || source.P95RTTNanos != nil {
		t.Fatalf("witnessed complete loss changed or gained latency: %+v", source)
	}
	if candidate := scan.stats(1); candidate.Transmitted != 4 || candidate.Replies != 2 || !candidate.Reachable ||
		candidate.LossRatio != "1/2" || candidate.P95RTTNanos == nil || *candidate.P95RTTNanos != "20" {
		t.Fatalf("candidate packet population or p95 changed: %+v", candidate)
	}
	foreign := candidateLast
	foreign.TenantID = "tenant-b"
	if err := scan.add(foreign); !errors.Is(err, entity.ErrScopeMismatch) {
		t.Fatalf("foreign evidence reached the comparison: %v", err)
	}
	if err := scan.add(candidateLast); err != nil || scan.complete() {
		t.Fatalf("duplicate round became a complete comparison: %v", err)
	}
}
