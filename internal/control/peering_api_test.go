// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func TestPeeringAPIKeepsExactPublicIdentitiesAndQualifiedCompleteOutput(t *testing.T) {
	ctx, request, target, traffic := peeringSummaryFixture(t)
	input := flow.PeeringEstimateInput{ContextID: request.Target.Scope.ContextID, InterfaceID: request.Target.InterfaceID, PeerASN: ^uint32(0), IXID: "9223372036854775807", LANID: "9007199254740993", Direction: "inbound", From: request.From, To: request.To, BucketSeconds: request.BucketSeconds}
	parsed, err := peeringAPIRequest(request.Target.Scope.TenantID, input)
	if err != nil || parsed.Target.IXID != 9223372036854775807 || parsed.Target.LANID != 9007199254740993 || parsed.Target.PeerASN != ^uint32(0) {
		t.Fatal("peering API narrowed full IX/LAN/ASN identities", parsed, err)
	}
	for _, bad := range []string{"0", "01", "-1", "9223372036854775808", "9e1", " 71"} {
		copyInput := input
		copyInput.IXID = bad
		if got, err := peeringAPIRequest(request.Target.Scope.TenantID, copyInput); err == nil || !reflect.DeepEqual(got, peeringEstimateRequest{}) {
			t.Fatal("peering API accepted an inexact public identity", bad, err)
		}
	}
	request.Target = parsed.Target
	target.Target = parsed.Target
	result, err := summarizePeeringTraffic(ctx, request, target, traffic, flowstore.DefaultExplorerBudget())
	if err != nil {
		t.Fatal(err)
	}
	response := projectPeeringResponse(result)
	raw, err := json.Marshal(response)
	if err != nil || !response.Preview || response.Target.IXID != input.IXID || response.Target.LANID != input.LANID || response.P95 == nil || response.P95.BitsPerSecondNumerator != "101000000000" || !response.Coverage.CompleteObservedInputs || !strings.Contains(response.Interpretation, "No lossless-telemetry") {
		t.Fatal("public peering response lost exact values or qualification", string(raw), err)
	}
	for _, private := range []string{"input_digest", "routing_capture_key", "raw_flow_digest", "source_sql", "TenantID"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("peering response exposed private source authority", private)
		}
	}
	result.Bytes["observed"] = "0"
	if response.Bytes["observed"] == "0" {
		t.Fatal("public peering response aliases mutable source counters")
	}
}

func TestPeeringHTTPRefusesTenantAndAuthorityHintsBeforeServiceReads(t *testing.T) {
	_, request, _, _ := peeringSummaryFixture(t)
	server := &Server{}
	for _, tenant := range []string{request.Target.Scope.TenantID, "66666666-6666-4666-8666-666666666666"} {
		for _, hint := range []string{"tenant_id", "router_id", "routing_capture_key", "complete", "input_digest"} {
			body := `{"context_id":"` + request.Target.Scope.ContextID + `","interface_id":"` + request.Target.InterfaceID + `","peer_asn":4294967295,"ix_id":"71","ix_lan_id":"11","direction":"inbound","` + hint + `":"untrusted"}`
			r := httptest.NewRequest(http.MethodPost, "/v1/flows/peering-estimate", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r = r.WithContext(auth.WithPrincipal(t.Context(), &auth.Principal{TenantID: tenant, UserID: "current-user"}))
			if err := server.handlePeeringEstimate(httptest.NewRecorder(), r); err == nil || !strings.Contains(err.Error(), "invalid JSON") {
				t.Fatal("served peering accepted client authority or reached a missing backend", tenant, hint, err)
			}
		}
	}
}
