// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"testing"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"google.golang.org/protobuf/proto"
)

func TestPublicRoutingClientKeepsOriginalFramesAndRequiresExclusiveReceipts(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	table := &agentv1.PublicRoutingPeerTable{ObservationId: id, ConfiguredRef: "ris/mrt_table_dump_v2/rrc00", ObservedUnixNanos: 123, SourceRecord: []byte{0, 0, 0, 1, 0, 13, 0, 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0}}
	stage := &agentv1.PublicRoutingStagingReceipt{Status: "staged", SnapshotId: id}
	stub := &routingReceiptClient{response: &agentv1.SubmitEntityEvidenceResponse{PublicRouting: stage}}
	client := &EvidenceClient{svc: stub}
	if got, err := client.StagePublicRoutingSource(t.Context(), table); err != nil || !proto.Equal(got, stage) || !proto.Equal(stub.request.PublicRoutingPeerTable, table) {
		t.Fatal("public routing client changed original source metadata or receipt", got, err)
	}
	for _, response := range []*agentv1.SubmitEntityEvidenceResponse{nil, {}, {PublicRouting: &agentv1.PublicRoutingStagingReceipt{Status: "current", SnapshotId: id}}, {PublicRouting: &agentv1.PublicRoutingStagingReceipt{Status: "staged", SnapshotId: "22222222-2222-4222-8222-222222222222"}}, {PublicRouting: stage, Accepted: 1}, {PublicRouting: stage, Routing: &agentv1.BmpRoutingStagingReceipt{}}, {PublicRouting: stage, PublicRoutingMessage: &agentv1.PublicRoutingMessageReceipt{}}} {
		stub.response = response
		if _, err := client.StagePublicRoutingSource(t.Context(), table); err == nil {
			t.Fatal("public routing staging accepted a foreign, mixed or published receipt")
		}
	}
	message := &agentv1.PublicRoutingMessage{ConfiguredRef: table.ConfiguredRef, SnapshotId: id, ObservedUnixNanos: 456, Sequence: 1, Record: []byte{0, 1, 2, 255}}
	receipt := &agentv1.PublicRoutingMessageReceipt{Status: "applied", SnapshotId: id, Sequence: 1}
	stub.response = &agentv1.SubmitEntityEvidenceResponse{PublicRoutingMessage: receipt}
	if got, err := client.SubmitPublicRoutingMessage(t.Context(), message); err != nil || !proto.Equal(got, receipt) || !proto.Equal(stub.request.PublicRoutingMessage, message) {
		t.Fatal("public routing client changed original record or sequence", got, err)
	}
	for _, response := range []*agentv1.SubmitEntityEvidenceResponse{nil, {}, {PublicRoutingMessage: receipt, FaultsPersisted: 1}, {PublicRoutingMessage: receipt, FlowRouting: &agentv1.FlowRoutingCaptureBatch{}}, {PublicRoutingMessage: receipt, PublicRouting: stage}, {PublicRoutingMessage: &agentv1.PublicRoutingMessageReceipt{Status: "applied", SnapshotId: id, Sequence: 2}}, {PublicRoutingMessage: &agentv1.PublicRoutingMessageReceipt{Status: "invalidated", SnapshotId: id, Sequence: 1}}} {
		stub.response = response
		if _, err := client.SubmitPublicRoutingMessage(t.Context(), message); err == nil {
			t.Fatal("public routing message accepted a foreign, mixed or invalidated receipt")
		}
	}
	stub.response = &agentv1.SubmitEntityEvidenceResponse{PublicRoutingMessage: &agentv1.PublicRoutingMessageReceipt{Status: "invalidated", SnapshotId: id, Sequence: 1}}
	message.Record = nil
	message.SourceReset = true
	if _, err := client.SubmitPublicRoutingMessage(t.Context(), message); err != nil {
		t.Fatal("source reset did not acknowledge committed invalidation", err)
	}
	message.Complete = true
	if _, err := client.SubmitPublicRoutingMessage(t.Context(), message); err == nil {
		t.Fatal("public routing client mixed EOF and reset")
	}
	message.Complete, message.SourceReset = false, false
	if _, err := client.SubmitPublicRoutingMessage(t.Context(), message); err == nil {
		t.Fatal("public routing client manufactured completion from empty data")
	}
}
