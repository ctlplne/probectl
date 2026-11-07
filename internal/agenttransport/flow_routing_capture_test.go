// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
)

func flowWitnessRequestForTest() *agentv1.SubmitEntityEvidenceRequest {
	raw := &agentv1.FlowRoutingWitness{RawDigest: make([]byte, 32), ExporterAddress: "::ffff:192.0.2.1", SourceAddress: "::", DestinationAddress: "2001:db8::1", FlowProtocol: "ipfix", ObservationDomain: ^uint32(0)}
	raw.RawDigest[31] = 1
	return &agentv1.SubmitEntityEvidenceRequest{FlowRouting: &agentv1.FlowRoutingWitnessBatch{ContractVersion: "flow_capture_v1", Observations: []*agentv1.FlowRoutingWitness{raw}}}
}

func TestFlowRoutingWitnessReceiverKeepsCompleteBatchAndCertifiedScope(t *testing.T) {
	id := crypto.SPIFFEID{TrustDomain: crypto.TrustDomain, Plane: "entity", TenantID: "11111111-1111-4111-8111-111111111111", AgentID: "22222222-2222-4222-8222-222222222222"}
	req := flowWitnessRequestForTest()
	first := req.FlowRouting.Observations[0]
	for i := 1; i < 501; i++ {
		item := proto.Clone(first).(*agentv1.FlowRoutingWitness)
		item.ObservationDomain = uint32(i)
		req.FlowRouting.Observations = append(req.FlowRouting.Observations, item)
	}
	original := proto.Clone(req)
	budget := store.BGPRoutingBudget{MemoryBytes: 128 << 20, WorkUnits: 128 << 20}
	got, err := parseFlowRoutingWitnessBatch(id, req, budget)
	if err != nil || len(got) != 501 || got[0].input.Domain != ^uint32(0) || got[0].input.Exporter.String() != "192.0.2.1" || got[0].digest[31] != 1 {
		t.Fatal("complete certified witness batch lost data or was truncated", err)
	}
	for i := 1; i < len(got); i++ {
		if got[i].input.Domain != uint32(i) {
			t.Fatal("witness receiver changed complete order")
		}
	}
	if !proto.Equal(req, original) {
		t.Fatal("witness receiver rewrote untrusted source bytes")
	}
	for _, changed := range []crypto.SPIFFEID{{TrustDomain: crypto.TrustDomain, Plane: "agent", TenantID: id.TenantID, AgentID: id.AgentID}, {TrustDomain: "foreign", Plane: "entity", TenantID: id.TenantID, AgentID: id.AgentID}, {TrustDomain: crypto.TrustDomain, Plane: "entity", TenantID: "foreign", AgentID: id.AgentID}} {
		if partial, err := parseFlowRoutingWitnessBatch(changed, req, budget); err == nil || partial != nil {
			t.Fatal("unverified identity produced a scoped witness batch")
		}
	}
	for _, b := range []store.BGPRoutingBudget{{MemoryBytes: 1, WorkUnits: 128 << 20}, {MemoryBytes: 128 << 20, WorkUnits: 1}} {
		if partial, err := parseFlowRoutingWitnessBatch(id, req, b); status.Code(err) != codes.ResourceExhausted || partial != nil {
			t.Fatal("whole witness batch escaped resource admission", err)
		}
	}
}

func TestFlowRoutingWitnessReceiverRefusesMixedMalformedAndUnknownAuthority(t *testing.T) {
	id := crypto.SPIFFEID{TrustDomain: crypto.TrustDomain, Plane: "entity", TenantID: "11111111-1111-4111-8111-111111111111", AgentID: "22222222-2222-4222-8222-222222222222"}
	budget := store.BGPRoutingBudget{MemoryBytes: 128 << 20, WorkUnits: 128 << 20}
	unknown := protowire.AppendTag(nil, 99, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, []byte("claimed-context-or-sender"))
	for _, mutate := range []func(*agentv1.SubmitEntityEvidenceRequest){
		func(v *agentv1.SubmitEntityEvidenceRequest) { v.FlowRouting.ContractVersion = "future" },
		func(v *agentv1.SubmitEntityEvidenceRequest) { v.FlowRouting.Observations = nil },
		func(v *agentv1.SubmitEntityEvidenceRequest) {
			v.FlowRouting.Observations = append(v.FlowRouting.Observations, nil)
		},
		func(v *agentv1.SubmitEntityEvidenceRequest) {
			v.FlowRouting.Observations[0].RawDigest = make([]byte, 31)
		},
		func(v *agentv1.SubmitEntityEvidenceRequest) { clear(v.FlowRouting.Observations[0].RawDigest) },
		func(v *agentv1.SubmitEntityEvidenceRequest) {
			v.FlowRouting.Observations[0].ExporterAddress = "224.0.0.1"
		},
		func(v *agentv1.SubmitEntityEvidenceRequest) {
			v.FlowRouting.Observations[0].SourceAddress = "fe80::1%other"
		},
		func(v *agentv1.SubmitEntityEvidenceRequest) { v.FlowRouting.Observations[0].DestinationAddress = "bad" },
		func(v *agentv1.SubmitEntityEvidenceRequest) { v.FlowRouting.Observations[0].FlowProtocol = "future" },
		func(v *agentv1.SubmitEntityEvidenceRequest) {
			v.Observations = []*agentv1.EntityEvidenceObservation{{}}
		},
		func(v *agentv1.SubmitEntityEvidenceRequest) { v.Faults = []*agentv1.EntityFaultObservation{{}} },
		func(v *agentv1.SubmitEntityEvidenceRequest) { v.RoutingPeerUp = &agentv1.BmpRoutingPeerUp{} },
		func(v *agentv1.SubmitEntityEvidenceRequest) { v.RoutingMessage = &agentv1.BmpRoutingMessage{} },
		func(v *agentv1.SubmitEntityEvidenceRequest) { v.ProtoReflect().SetUnknown(unknown) },
		func(v *agentv1.SubmitEntityEvidenceRequest) { v.FlowRouting.ProtoReflect().SetUnknown(unknown) },
		func(v *agentv1.SubmitEntityEvidenceRequest) {
			v.FlowRouting.Observations[0].ProtoReflect().SetUnknown(unknown)
		},
	} {
		req := flowWitnessRequestForTest()
		mutate(req)
		if partial, err := parseFlowRoutingWitnessBatch(id, req, budget); err == nil || partial != nil {
			t.Fatal("malformed or authority-bearing witness exposed a partial batch", err)
		}
	}
}
