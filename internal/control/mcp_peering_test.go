// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func TestPeeringNativeProjectionKeepsWholePublicContractAndExactMetadata(t *testing.T) {
	ctx, request, target, traffic := peeringSummaryFixture(t)
	result, err := summarizePeeringTraffic(ctx, request, target, traffic, flowstore.DefaultExplorerBudget())
	if err != nil {
		t.Fatal(err)
	}
	response := projectPeeringResponse(result)
	response.Target.IXID = "9223372036854775807"
	response.Target.LANID = "9007199254740993"
	response.Target.MemberIDs = make([]string, 5001)
	for i := range response.Target.MemberIDs {
		response.Target.MemberIDs[i] = "untrusted/evidence/source"
	}
	raw, err := marshalNativePeeringResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	var decoded flow.PeeringEstimateResponse
	if err := json.Unmarshal(raw, &decoded); err != nil || !reflect.DeepEqual(response, decoded) {
		t.Fatal("native peering projection lost complete exact API semantics", err)
	}
	schemas, err := peeringToolOption(&Server{})
	if err != nil || schemas == nil {
		t.Fatal("peering native schema diverged from the API", err)
	}
}

func TestPeeringNativeUnprovenSelectorsRetainMandatoryPIIRedaction(t *testing.T) {
	_, request, target, _ := peeringSummaryFixture(t)
	target.Target = request.Target
	target.Eligible = false
	target.Reason = "source_unavailable"
	value := projectPeeringResponse(peeringEstimateResult{Target: target, Direction: "inbound", Reason: "source_unavailable"})
	// A caller can supply any canonical positive int64 before a public source
	// proves it is an IX identity. It must not become trusted metadata merely
	// because parsing succeeded. The card is the standing synthetic PAN fixture.
	value.Target.IXID = "4111111111111111"
	value.Target.LANID = value.Target.IXID
	raw, err := marshalNativePeeringResponse(value)
	if err != nil {
		t.Fatal(err)
	}
	gate := ai.NewEgressGate(nil, nil, ai.RedactionPolicy{})
	redacted := gate.RedactForTenant(string(raw), request.Target.Scope.TenantID)
	var decoded flow.PeeringEstimateResponse
	if err := json.Unmarshal([]byte(redacted), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Target.IXID == value.Target.IXID || decoded.Target.LANID == value.Target.LANID {
		t.Fatal("unproven peering selector bypassed mandatory PAN redaction")
	}
}
