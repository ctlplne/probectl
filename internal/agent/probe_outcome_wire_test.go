// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"testing"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestProbeOutcomeWireRequiresCompleteTypedReceipt(t *testing.T) {
	request := &agentv1.SubmitEntityEvidenceRequest{Observations: []*agentv1.EntityEvidenceObservation{
		{Icmp: &agentv1.IcmpMeasurement{Version: 1}},
		{ProbeOutcome: &agentv1.ProbeOutcome{Version: 1}},
		{},
	}}
	good := &agentv1.SubmitEntityEvidenceResponse{Accepted: 3, IcmpMeasurementsPersisted: 1, ProbeOutcomesPersisted: 1}
	if !validICMPEvidenceReceipt(request, good) {
		t.Fatal("complete mixed metadata receipt refused")
	}
	if !validICMPEvidenceReceipt(request, &agentv1.SubmitEntityEvidenceResponse{Accepted: 1, Unresolved: 2}) {
		t.Fatal("explicit unresolved typed observations were acknowledged as retained or refused")
	}
	for name, mutate := range map[string]func(*agentv1.SubmitEntityEvidenceResponse){
		"legacy outcome omission": func(r *agentv1.SubmitEntityEvidenceResponse) { r.ProbeOutcomesPersisted = 0 },
		"ICMP omission":           func(r *agentv1.SubmitEntityEvidenceResponse) { r.IcmpMeasurementsPersisted = 0 },
		"extra outcome":           func(r *agentv1.SubmitEntityEvidenceResponse) { r.ProbeOutcomesPersisted = 2 },
		"incomplete population":   func(r *agentv1.SubmitEntityEvidenceResponse) { r.Accepted = 2 },
		"unrelated fault":         func(r *agentv1.SubmitEntityEvidenceResponse) { r.FaultsPersisted = 1 },
		"unknown response":        func(r *agentv1.SubmitEntityEvidenceResponse) { r.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1}) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := &agentv1.SubmitEntityEvidenceResponse{Accepted: 3, IcmpMeasurementsPersisted: 1, ProbeOutcomesPersisted: 1}
			mutate(bad)
			if validICMPEvidenceReceipt(request, bad) {
				t.Fatal("incomplete or cross-plane evidence ack accepted")
			}
		})
	}
	if validICMPEvidenceReceipt(request, nil) || validICMPEvidenceReceipt(nil, good) {
		t.Fatal("missing evidence population acquired a valid receipt")
	}
	request.Observations[0].ProbeOutcome = &agentv1.ProbeOutcome{Version: 1}
	if validICMPEvidenceReceipt(request, good) {
		t.Fatal("one observation acknowledged two incompatible metadata families")
	}
}
