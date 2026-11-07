// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type routingReceiptClient struct {
	agentv1.AgentServiceClient
	request  *agentv1.SubmitEntityEvidenceRequest
	response *agentv1.SubmitEntityEvidenceResponse
}

func (c *routingReceiptClient) SubmitEntityEvidence(_ context.Context, req *agentv1.SubmitEntityEvidenceRequest, _ ...grpc.CallOption) (*agentv1.SubmitEntityEvidenceResponse, error) {
	c.request = proto.Clone(req).(*agentv1.SubmitEntityEvidenceRequest)
	return c.response, nil
}

func TestRoutingStageClientPreservesCompleteRequestAndRequiresPrivateReceipt(t *testing.T) {
	raw := &agentv1.BmpRoutingPeerUp{ObservationId: "11111111-1111-4111-8111-111111111111", ConfiguredRef: "owned-router", OriginSerial: "abcd", ObservedUnixNanos: 123, Message: []byte{0, 1, 2, 255}}
	good := &agentv1.BmpRoutingStagingReceipt{Status: "staged", Views: []*agentv1.BmpRoutingViewReference{{Id: "22222222-2222-4222-8222-222222222222", Generation: raw.ObservationId, Afi: 1, Safi: 1}}}
	stub := &routingReceiptClient{response: &agentv1.SubmitEntityEvidenceResponse{Routing: good}}
	client := &EvidenceClient{svc: stub}
	receipt, err := client.StageRoutingPeer(t.Context(), raw)
	if err != nil || !proto.Equal(receipt, good) || !proto.Equal(stub.request.GetRoutingPeerUp(), raw) || len(stub.request.GetObservations())+len(stub.request.GetFaults()) != 0 {
		t.Fatal("routing staging client changed complete request or accepted observation publication", err)
	}
	for _, response := range []*agentv1.SubmitEntityEvidenceResponse{
		nil, {},
		{Routing: &agentv1.BmpRoutingStagingReceipt{Status: "invalidated"}}, {Routing: &agentv1.BmpRoutingStagingReceipt{Status: "current", Views: good.Views}},
		{Routing: &agentv1.BmpRoutingStagingReceipt{Status: "staged"}},
		{Routing: &agentv1.BmpRoutingStagingReceipt{Status: "invalidated", Views: good.Views}},
		{Accepted: 1, Routing: good},
		{FlowRouting: &agentv1.FlowRoutingCaptureBatch{}, Routing: good},
		{RoutingMessage: &agentv1.BmpRoutingMessageReceipt{}, Routing: good},
	} {
		stub.response = response
		if _, err := client.StageRoutingPeer(context.Background(), raw); err == nil {
			t.Fatal("routing staging accepted missing, partial or published receipt")
		}
	}
}
