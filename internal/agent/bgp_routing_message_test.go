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

func TestRoutingMessageClientKeepsExactStreamAndRefusesMixedReceipts(t *testing.T) {
	raw := &agentv1.BmpRoutingMessage{ConfiguredRef: "owned-router", OriginSerial: "abcd", Generation: "11111111-1111-4111-8111-111111111111", Sequence: 7, ObservedUnixNanos: 123, Message: []byte{0, 255, 1}}
	good := &agentv1.BmpRoutingMessageReceipt{Status: "applied", Generation: raw.Generation, Sequence: raw.Sequence}
	stub := &routingReceiptClient{response: &agentv1.SubmitEntityEvidenceResponse{RoutingMessage: good}}
	client := &EvidenceClient{svc: stub}
	if got, err := client.SubmitRoutingMessage(t.Context(), raw); err != nil || !proto.Equal(got, good) || !proto.Equal(stub.request.GetRoutingMessage(), raw) || stub.request.GetRoutingPeerUp() != nil {
		t.Fatal("ordered routing client changed complete source message", err)
	}
	for _, response := range []*agentv1.SubmitEntityEvidenceResponse{
		nil, {}, {RoutingMessage: &agentv1.BmpRoutingMessageReceipt{Status: "invalidated", Generation: raw.Generation, Sequence: raw.Sequence}},
		{Accepted: 1, RoutingMessage: good}, {Routing: &agentv1.BmpRoutingStagingReceipt{}, RoutingMessage: good},
		{RoutingMessage: &agentv1.BmpRoutingMessageReceipt{Status: "applied", Generation: raw.Generation, Sequence: 8}},
		{RoutingMessage: &agentv1.BmpRoutingMessageReceipt{Status: "applied", Generation: "22222222-2222-4222-8222-222222222222", Sequence: raw.Sequence}},
		{RoutingMessage: &agentv1.BmpRoutingMessageReceipt{Status: "current", Generation: raw.Generation, Sequence: raw.Sequence}},
	} {
		stub.response = response
		if _, err := client.SubmitRoutingMessage(t.Context(), raw); err == nil {
			t.Fatal("ordered routing client accepted partial or unrelated receipt")
		}
	}
}
