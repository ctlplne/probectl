// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestICMPEgressWireRetainsTheLocalWitness(t *testing.T) {
	host, schedule, result, _ := probeQueueFixture(t, "north", "north-agent")
	measurement := result.ICMP
	measurement.TargetIP = "198.51.100.18"
	measurement.Responders = []string{measurement.TargetIP}
	measurement.RoundTripNanos = []uint64{10, 20, 30}
	measurement.ExecutionNanos = uint64(time.Millisecond)
	wire := func() *agentv1.IcmpMeasurement {
		t.Helper()
		observation, err := host.probeObservation(schedule, result)
		if err != nil {
			t.Fatal(err)
		}
		body, err := proto.Marshal(encodeICMPMeasurement(observation.ICMP))
		if err != nil {
			t.Fatal(err)
		}
		var decoded agentv1.IcmpMeasurement
		if err := proto.Unmarshal(body, &decoded); err != nil {
			t.Fatal(err)
		}
		return &decoded
	}
	if ordinary := wire(); ordinary.GetVersion() != 3 || ordinary.GetEgress() != nil {
		t.Fatal("the ordinary probe gained an egress witness", ordinary)
	}
	measurement.Egress = &canary.ICMPEgressMeasurement{
		ICMPEgress: canary.ICMPEgress{
			Interface: "eth0", Source: netip.MustParseAddr("192.0.2.3"),
			PeerMAC: [6]byte{0x02, 0, 0, 0, 0, 4},
		},
		Transmitted: 3,
	}
	bound := wire()
	want := &agentv1.IcmpEgressWitness{Interface: "eth0", Source: "192.0.2.3", PeerMac: "02:00:00:00:00:04", Transmitted: 3}
	if bound.GetVersion() != entity.ICMPVersionEgress || !proto.Equal(bound.GetEgress(), want) ||
		len(bound.GetRoundTrips().GetNanos()) != 3 {
		t.Fatal("the local witness or original measurement was lost on the wire", bound)
	}

	measurement.Egress.Transmitted--
	if _, err := host.probeObservation(schedule, result); err == nil {
		t.Fatal("a partial local witness was accepted")
	}
}

func TestICMPNetworkErrorWireRetainsCompleteConfiguredPopulation(t *testing.T) {
	const count = 100000
	at := time.Now().UTC().Truncate(time.Microsecond)
	measurement := &entity.ICMPMeasurement{Version: 2, DefinitionHash: strings.Repeat("a", 64), StartedAt: at.Add(-time.Second), CompletedAt: at,
		Requested: count, Attempted: count, Transmitted: count, ReadComplete: true}
	for i := range count {
		measurement.NetworkErrors = append(measurement.NetworkErrors, entity.ICMPNetworkError{Sequence: uint32(i),
			Responder: "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", Type: 1, Code: 0, ReceivedAt: at, PacketDigest: strings.Repeat("a", 64)})
	}
	observation := entity.Observation{ID: "bf806db0-b5ae-4059-998d-97b9c7226a05", Source: entity.SourceKey{AgentID: "agent-one", Kind: entity.PathAgent, SourceRef: "e3fed09f-a38f-4637-9a6d-ef8471b6e7ca"},
		Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "2001:db8::99"}, SourceRef: "icmp:configured-test", ObservedAt: at, ICMP: measurement}
	client := &EvidenceClient{agentID: "agent-one", svc: agentv1.NewAgentServiceClient(nil)}
	request, err := client.encodeEvidence(at, []entity.Observation{observation})
	if err != nil {
		t.Fatal("complete configured network-error population refused", err)
	}
	t.Logf("complete %d-error wire population: %d bytes", count, proto.Size(request))
	retained := request.Observations[0].Icmp.NetworkErrors
	if len(retained) != count || retained[count-1].Sequence != count-1 || len(retained[count-1].PacketDigest) != 32 {
		t.Fatal("complete population, full sequence or digest was truncated")
	}
}

func TestICMPEvidenceReceiptRefusesLegacyOmissionAndUnrelatedPlane(t *testing.T) {
	request := &agentv1.SubmitEntityEvidenceRequest{Observations: []*agentv1.EntityEvidenceObservation{{Icmp: &agentv1.IcmpMeasurement{Version: 1}}, {Icmp: &agentv1.IcmpMeasurement{Version: 1}}}}
	good := &agentv1.SubmitEntityEvidenceResponse{Accepted: 2, IcmpMeasurementsPersisted: 2}
	if !validICMPEvidenceReceipt(request, good) {
		t.Fatal("complete typed receipt refused")
	}
	if !validICMPEvidenceReceipt(request, &agentv1.SubmitEntityEvidenceResponse{Accepted: 1, Unresolved: 1, IcmpMeasurementsPersisted: 1}) {
		t.Fatal("explicit unresolved source was converted to a successful prefix")
	}
	mutations := map[string]func(*agentv1.SubmitEntityEvidenceResponse){
		"legacy omitted typed receipt": func(r *agentv1.SubmitEntityEvidenceResponse) { r.IcmpMeasurementsPersisted = 0 },
		"partial typed receipt":        func(r *agentv1.SubmitEntityEvidenceResponse) { r.IcmpMeasurementsPersisted = 1 },
		"excess receipt":               func(r *agentv1.SubmitEntityEvidenceResponse) { r.IcmpMeasurementsPersisted = 3 },
		"missing population":           func(r *agentv1.SubmitEntityEvidenceResponse) { r.Accepted = 1; r.IcmpMeasurementsPersisted = 1 },
		"fault plane":                  func(r *agentv1.SubmitEntityEvidenceResponse) { r.FaultsPersisted = 1 },
		"routing plane":                func(r *agentv1.SubmitEntityEvidenceResponse) { r.Routing = &agentv1.BmpRoutingStagingReceipt{} },
		"unknown field":                func(r *agentv1.SubmitEntityEvidenceResponse) { r.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1}) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			bad := proto.Clone(good).(*agentv1.SubmitEntityEvidenceResponse)
			mutate(bad)
			if validICMPEvidenceReceipt(request, bad) {
				t.Fatal("omitted or mismatched evidence was acknowledged")
			}
		})
	}
	if validICMPEvidenceReceipt(request, nil) {
		t.Fatal("missing response acknowledged")
	}
}

func TestICMPRoundTripWireRetainsCompleteOriginalPopulationAndEmptyPresence(t *testing.T) {
	const count = 100000
	at := time.Now().UTC().Truncate(time.Microsecond)
	for _, replies := range []uint32{0, count} {
		samples := make([]uint64, replies)
		for index := range samples {
			samples[index] = uint64(index + 1)
		}
		measurement := &entity.ICMPMeasurement{Version: 3, DefinitionHash: strings.Repeat("a", 64), StartedAt: at.Add(-time.Second), CompletedAt: at, Requested: count, Attempted: count, Transmitted: count, Replies: replies, ReadComplete: true, Responders: []string{}, RoundTrips: &entity.ICMPRoundTrips{Nanos: samples, ExecutionNanos: uint64(time.Second)}}
		if replies > 0 {
			measurement.Responders = []string{"2001:db8::99"}
		}
		observation := entity.Observation{ID: "bf806db0-b5ae-4059-998d-97b9c7226a05", Source: entity.SourceKey{AgentID: "agent-one", Kind: entity.PathAgent, SourceRef: "e3fed09f-a38f-4637-9a6d-ef8471b6e7ca"}, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "2001:db8::99"}, SourceRef: "icmp:configured-test", ObservedAt: at, ICMP: measurement}
		client := &EvidenceClient{agentID: "agent-one", svc: agentv1.NewAgentServiceClient(nil)}
		request, err := client.encodeEvidence(at, []entity.Observation{observation})
		if err != nil {
			t.Fatal("complete original RTT population refused", replies, err)
		}
		body, err := proto.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var decoded agentv1.SubmitEntityEvidenceRequest
		if err := proto.Unmarshal(body, &decoded); err != nil {
			t.Fatal(err)
		}
		retained := decoded.Observations[0].Icmp.RoundTrips
		if retained == nil || len(retained.Nanos) != int(replies) {
			t.Fatal("RTT absence/empty/population changed on wire", replies)
		}
		for index, value := range retained.Nanos {
			if value != samples[index] {
				t.Fatal("original sample changed on wire", index)
			}
		}
		if proto.Size(request) > entity.MaxICMPMeasurementWireBytes {
			t.Fatal("complete request bypassed finite wire admission")
		}
	}
}
