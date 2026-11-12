// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestFlowRoutingClientRequiresCompleteOrderedCertifiedReceipts(t *testing.T) {
	raw := []*agentv1.FlowRoutingWitness{{RawDigest: make([]byte, 32), ExporterAddress: "192.0.2.1", SourceAddress: "203.0.113.1", DestinationAddress: "2001:db8::1", FlowProtocol: "ipfix", ObservationDomain: ^uint32(0)}}
	raw[0].RawDigest[31] = 1
	raw = append(raw, proto.Clone(raw[0]).(*agentv1.FlowRoutingWitness))
	raw[1].RawDigest[0] = 2
	stub := &routingReceiptClient{}
	client := &EvidenceClient{svc: stub, tenantID: "11111111-1111-4111-8111-111111111111", agentID: "22222222-2222-4222-8222-222222222222"}
	good := &agentv1.SubmitEntityEvidenceResponse{FlowRouting: &agentv1.FlowRoutingCaptureBatch{}}
	for i, item := range raw {
		key, err := flowWitnessKey(client.tenantID, client.agentID, item)
		if err != nil {
			t.Fatal(err)
		}
		good.FlowRouting.Captures = append(good.FlowRouting.Captures, &agentv1.FlowRoutingCapture{Key: append([]byte(nil), key[:]...), CapturedUnixNanos: int64(i + 1)})
	}
	stub.response = good
	got, err := client.SubmitFlowRouting(t.Context(), raw)
	if err != nil || len(got) != 2 || !proto.Equal(got[0], good.FlowRouting.Captures[0]) || !proto.Equal(stub.request.GetFlowRouting().Observations[1], raw[1]) || len(stub.request.GetObservations())+len(stub.request.GetFaults()) != 0 || stub.request.GetRoutingPeerUp() != nil || stub.request.GetRoutingMessage() != nil {
		t.Fatal("flow witness client changed complete exclusive request or receipt", err)
	}
	got[0].Key[0] ^= 1
	if bytes.Equal(got[0].Key, good.FlowRouting.Captures[0].Key) {
		t.Fatal("flow witness receipt retained mutable transport storage")
	}
	for _, mutate := range []func(*agentv1.SubmitEntityEvidenceResponse){
		func(v *agentv1.SubmitEntityEvidenceResponse) { v.IcmpMeasurementsPersisted = 1 },
		func(v *agentv1.SubmitEntityEvidenceResponse) { v.FlowRouting = nil },
		func(v *agentv1.SubmitEntityEvidenceResponse) { v.FlowRouting.Captures = v.FlowRouting.Captures[:1] },
		func(v *agentv1.SubmitEntityEvidenceResponse) { v.FlowRouting.Captures[0] = nil },
		func(v *agentv1.SubmitEntityEvidenceResponse) { v.FlowRouting.Captures[0].Key[31] ^= 1 },
		func(v *agentv1.SubmitEntityEvidenceResponse) { v.FlowRouting.Captures[0].CapturedUnixNanos = 0 },
		func(v *agentv1.SubmitEntityEvidenceResponse) {
			v.FlowRouting.Captures[0], v.FlowRouting.Captures[1] = v.FlowRouting.Captures[1], v.FlowRouting.Captures[0]
		},
		func(v *agentv1.SubmitEntityEvidenceResponse) { v.Accepted = 1 },
		func(v *agentv1.SubmitEntityEvidenceResponse) { v.Unresolved = 1 },
		func(v *agentv1.SubmitEntityEvidenceResponse) { v.FaultsPersisted = 1 },
		func(v *agentv1.SubmitEntityEvidenceResponse) { v.Routing = &agentv1.BmpRoutingStagingReceipt{} },
		func(v *agentv1.SubmitEntityEvidenceResponse) { v.RoutingMessage = &agentv1.BmpRoutingMessageReceipt{} },
		func(v *agentv1.SubmitEntityEvidenceResponse) { v.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1}) },
		func(v *agentv1.SubmitEntityEvidenceResponse) {
			v.FlowRouting.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1})
		},
		func(v *agentv1.SubmitEntityEvidenceResponse) {
			v.FlowRouting.Captures[0].ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1})
		},
	} {
		response := proto.Clone(good).(*agentv1.SubmitEntityEvidenceResponse)
		mutate(response)
		stub.response = response
		if partial, err := client.SubmitFlowRouting(t.Context(), raw); err == nil || partial != nil {
			t.Fatal("flow witness client accepted mixed foreign or partial receipt", err)
		}
	}
	stub.response = good
	raw[1].RawDigest = nil
	stub.request = nil
	if partial, err := client.SubmitFlowRouting(t.Context(), raw); err == nil || partial != nil || stub.request != nil {
		t.Fatal("invalid trailing witness reached transport or returned partial receipt", err)
	}
}
