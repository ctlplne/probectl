// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestBMPPeerSessionReceiptRequiresTypedRetention(t *testing.T) {
	request := &agentv1.SubmitEntityEvidenceRequest{BmpPeerSessions: &agentv1.BmpPeerSessionBatch{Observations: []*agentv1.EntityEvidenceObservation{{BmpPeerSession: &agentv1.BmpPeerSession{Frame: []byte{3}}}}}}
	if !validICMPEvidenceReceipt(request, &agentv1.SubmitEntityEvidenceResponse{Accepted: 1, BmpPeerSessionsPersisted: 1}) || !validICMPEvidenceReceipt(request, &agentv1.SubmitEntityEvidenceResponse{Unresolved: 1}) {
		t.Fatal("explicit session retention or unresolved source was lost")
	}
	for _, response := range []*agentv1.SubmitEntityEvidenceResponse{{Accepted: 1}, {Accepted: 1, InterfaceStatesPersisted: 1}, {Accepted: 1, BmpPeerSessionsPersisted: 2}, {Unresolved: 1, BmpPeerSessionsPersisted: 1}} {
		if validICMPEvidenceReceipt(request, response) {
			t.Fatal("unrelated or generic acknowledgment silently discarded session evidence")
		}
	}
	request.BmpPeerSessions.Observations[0].Icmp = &agentv1.IcmpMeasurement{}
	if validICMPEvidenceReceipt(request, &agentv1.SubmitEntityEvidenceResponse{Accepted: 1, BmpPeerSessionsPersisted: 1}) {
		t.Fatal("mixed typed families bypassed receipt accounting")
	}
}

func TestBMPPeerSessionClientUsesExclusiveLegacySafeEnvelope(t *testing.T) {
	raw := make([]byte, 49)
	raw[0], raw[5], raw[48] = 3, 2, 4
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	copy(raw[28:32], []byte{192, 0, 2, 7})
	binary.BigEndian.PutUint32(raw[32:36], 64500)
	fact, err := bgp.DecodePhysicalPeerSession(t.Context(), raw, bgp.PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	client := &EvidenceClient{agentID: "listener", svc: agentv1.NewAgentServiceClient(nil)}
	claim := entity.Observation{ID: id, Source: entity.SourceKey{AgentID: "listener", Kind: entity.BMPPeer, SourceRef: "router"}, Alias: entity.AliasKey{Kind: entity.BMPPeerAlias, Value: "192.0.2.7/as64500"}, SourceRef: "bmp:router:router:peer-asn:64500", OriginSerial: "abc", ObservedAt: time.Now().UTC(), BMPPeerSession: fact}
	request, err := client.encodeEvidence(time.Now(), []entity.Observation{claim})
	if err != nil || len(request.Observations) != 0 || request.BmpPeerSessions == nil || len(request.BmpPeerSessions.Observations) != 1 || !bytes.Equal(request.BmpPeerSessions.Observations[0].BmpPeerSession.Frame, raw) {
		t.Fatal("lifecycle client exposed a generic fallback", err)
	}
	body, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	oldFile := protodesc.ToFileDescriptorProto(agentv1.File_probectl_agent_v1_agent_proto)
	for _, message := range oldFile.MessageType {
		if message.GetName() == "SubmitEntityEvidenceRequest" {
			fields := message.Field[:0]
			for _, field := range message.Field {
				if field.GetNumber() != 9 {
					fields = append(fields, field)
				}
			}
			message.Field = fields
		}
	}
	descriptor, err := protodesc.NewFile(oldFile, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	legacy := dynamicpb.NewMessage(descriptor.Messages().ByName("SubmitEntityEvidenceRequest"))
	if err := proto.Unmarshal(body, legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Get(legacy.Descriptor().Fields().ByNumber(1)).List().Len() != 0 || legacy.Get(legacy.Descriptor().Fields().ByNumber(2)).List().Len() != 0 || len(legacy.GetUnknown()) == 0 {
		t.Fatal("old receiver could persist a generic peer identity from a down event")
	}
	if !validICMPEvidenceReceipt(request, &agentv1.SubmitEntityEvidenceResponse{Accepted: 1, BmpPeerSessionsPersisted: 1}) {
		t.Fatal("exclusive typed batch could not be acknowledged")
	}
}
