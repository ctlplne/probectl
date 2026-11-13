// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

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
