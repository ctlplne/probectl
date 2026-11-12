// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

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
