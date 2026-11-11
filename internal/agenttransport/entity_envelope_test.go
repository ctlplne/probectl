// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestEntityEvidenceEnvelopeKeepsOnePlaneAndRefusesUnknownPublicFields(t *testing.T) {
	kinds := []func(*agentv1.SubmitEntityEvidenceRequest){
		func(r *agentv1.SubmitEntityEvidenceRequest) { r.DeviceCounter = &agentv1.DeviceCounterWitness{} },
		func(r *agentv1.SubmitEntityEvidenceRequest) {
			r.Observations = []*agentv1.EntityEvidenceObservation{{}}
			r.Faults = []*agentv1.EntityFaultObservation{{}}
		},
		func(r *agentv1.SubmitEntityEvidenceRequest) { r.FlowRouting = &agentv1.FlowRoutingWitnessBatch{} },
		func(r *agentv1.SubmitEntityEvidenceRequest) { r.RoutingPeerUp = &agentv1.BmpRoutingPeerUp{} },
		func(r *agentv1.SubmitEntityEvidenceRequest) { r.RoutingMessage = &agentv1.BmpRoutingMessage{} },
		func(r *agentv1.SubmitEntityEvidenceRequest) {
			r.PublicRoutingPeerTable = &agentv1.PublicRoutingPeerTable{}
		},
		func(r *agentv1.SubmitEntityEvidenceRequest) { r.PublicRoutingMessage = &agentv1.PublicRoutingMessage{} },
	}
	if validEntityEvidenceEnvelope(nil) || validEntityEvidenceEnvelope(&agentv1.SubmitEntityEvidenceRequest{}) {
		t.Fatal("empty evidence envelope was accepted")
	}
	for i, kind := range kinds {
		raw := &agentv1.SubmitEntityEvidenceRequest{}
		kind(raw)
		if !validEntityEvidenceEnvelope(raw) {
			t.Fatal("complete evidence operation was refused", i)
		}
		unknown := proto.Clone(raw).(*agentv1.SubmitEntityEvidenceRequest)
		unknown.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		if validEntityEvidenceEnvelope(unknown) {
			t.Fatal("unknown evidence fields were partially accepted", i)
		}
		for j, other := range kinds {
			if i == j {
				continue
			}
			mixed := proto.Clone(raw).(*agentv1.SubmitEntityEvidenceRequest)
			other(mixed)
			if validEntityEvidenceEnvelope(mixed) {
				t.Fatal("mixed evidence planes were partially accepted", i, j)
			}
		}
	}
}
