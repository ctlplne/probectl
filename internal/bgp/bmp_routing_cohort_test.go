// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type routingCohortCapture struct{ routingSelectorsCapture }

func (c *routingCohortCapture) StageRoutingPeer(ctx context.Context, request *agentv1.BmpRoutingPeerUp) (*agentv1.BmpRoutingStagingReceipt, error) {
	c.stages = append(c.stages, proto.Clone(request).(*agentv1.BmpRoutingPeerUp))
	_, families, err := DecodeRoutingPeerUp(ctx, request.Message, PeerMessageBudget{16 << 20, 16 << 20})
	if err != nil {
		return nil, err
	}
	receipt := &agentv1.BmpRoutingStagingReceipt{Status: "staged"}
	for _, family := range families {
		receipt.Views = append(receipt.Views, &agentv1.BmpRoutingViewReference{Generation: request.ObservationId, Afi: uint32(family.AFI), Safi: uint32(family.SAFI)})
	}
	return receipt, nil
}

// Complete protocol frames with a modeled current-configuration RPC peer.
// Real TLS/current credentials/store and physical router proofs are separate.
func TestBMPRoutingCohortsKeepOneSocketFamiliesSequencesAndWholeReplacement(t *testing.T) {
	sink := &routingCohortCapture{}
	listener := NewBMPListener(nil, nil, "", nil, WithBMPTenantLane("tenant-a", "lane-a"), WithBMPEntityEvidence("listener-a", sink))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	id := bmpIdentity{TenantID: "tenant-a", AgentID: "router-a", Serial: "serial-a"}
	handle := listener.registerLive(&bmpLiveSession{id: id, cancel: cancel})
	other := listener.registerLive(&bmpLiveSession{id: id, cancel: func() {}})
	states := routingBookForTest()
	drive := func(session uint64, raw []byte) {
		t.Helper()
		var err error
		if raw[5] == 3 {
			err = listener.queueRoutingPeerUp(id, session, raw[6:])
		} else {
			err = listener.queueRoutingMessage(id, session, raw[5], raw[6:])
		}
		if err != nil {
			t.Fatal(err)
		}
		select {
		case peer := <-listener.evidenceQueue:
			listener.routingStreamEvidence(ctx, peer, states)
		default:
			t.Fatal("complete cohort frame never reached routing worker")
		}
	}
	up := func(session uint64, families ...byte) ([]byte, string) {
		t.Helper()
		caps := []byte{65, 4, 0, 0, 0, 1}
		for _, family := range families {
			caps = append(caps, 1, 4, 0, family, 0, 1)
		}
		open := routeOpenForTest(caps, false)
		raw := peerUpFrameForTest(open, open, nil)
		raw[6] = 3
		clear(raw[16:32])
		clear(raw[48:68])
		drive(session, raw)
		return raw, sink.stages[len(sink.stages)-1].ObservationId
	}
	v4, first := up(handle, 1)
	v6, second := up(handle, 2)
	_, sibling := up(other, 2)
	if len(states.sessions[handle]) != 2 {
		t.Fatal("one-socket disjoint family Peer Up replaced another cohort")
	}
	drive(handle, sourceRouteFrameForTest(v4[6:48], endOfRIBFrameForTest(nil, nil, nil)))
	drive(handle, sourceRouteFrameForTest(v6[6:48], endOfRIBFrameForTest(nil, []byte{128, 15, 3, 0, 2, 1}, nil)))
	data := []*agentv1.BmpRoutingMessage{}
	for _, message := range sink.messages {
		if !message.SourceReset {
			data = append(data, message)
		}
	}
	if len(data) != 2 || data[0].Generation != first || data[1].Generation != second || data[0].Sequence != 1 || data[1].Sequence != 1 {
		t.Fatal("family cohorts shared source generation or sequence", data)
	}
	combined, third := up(handle, 1, 2)
	if len(states.sessions[handle]) != 1 || len(states.sessions[other]) != 1 {
		t.Fatal("combined Peer Up lost whole overlap retirement or crossed a physical source")
	}
	drive(handle, sourceRouteFrameForTest(combined[6:48], endOfRIBFrameForTest(nil, nil, nil)))
	drive(handle, sourceRouteFrameForTest(combined[6:48], endOfRIBFrameForTest(nil, []byte{128, 15, 3, 0, 2, 1}, nil)))
	last := sink.messages[len(sink.messages)-1]
	if last.Generation != third || last.Sequence != 2 {
		t.Fatal("combined family cohort lost complete shared wire sequence", last)
	}
	_, fourth := up(handle, 1)
	reset := map[string]bool{}
	for _, message := range sink.messages {
		if message.SourceReset {
			reset[message.Generation] = true
		}
	}
	if !reset[first] || !reset[second] || !reset[third] || reset[sibling] || len(states.sessions[handle]) != 1 {
		t.Fatal("whole cohort replacement omitted a retired family or reset a sibling")
	}
	// Statistics have no complete AFI selector and advance the known cohort;
	// they cannot manufacture a family completion marker or another generation.
	stats := append(append([]byte(nil), v4[:48]...), 0, 0, 0, 0)
	stats[5] = 1
	binary.BigEndian.PutUint32(stats[1:5], uint32(len(stats)))
	drive(handle, stats)
	last = sink.messages[len(sink.messages)-1]
	if last.Generation != fourth || last.Sequence != 1 || !last.Heartbeat {
		t.Fatal("source statistics changed cohort ownership or sequence", last)
	}
	listener.endRoutingEvidence(ctx, id, handle)
	peer := <-listener.evidenceQueue
	listener.routingStreamEvidence(ctx, peer, states)
	if len(states.sessions[handle]) != 0 || len(states.sessions[other]) != 1 {
		t.Fatal("physical source closure leaked cohorts or changed a sibling socket")
	}
}

func TestRoutingCohortReceiptRequiresCompleteUniqueGeneration(t *testing.T) {
	for _, families := range [][]uint32{{1}, {2}, {1, 2}} {
		receipt := &agentv1.BmpRoutingStagingReceipt{Status: "staged"}
		var want uint8
		for _, afi := range families {
			receipt.Views = append(receipt.Views, &agentv1.BmpRoutingViewReference{Generation: "owned-generation", Afi: afi, Safi: 1})
			want |= 1 << (afi - 1)
		}
		if mask, ok := routingReceiptFamilyMask(receipt, "owned-generation"); !ok || mask != want {
			t.Fatal("complete supported receipt lost cohort", mask, want)
		}
	}
	for _, receipt := range []*agentv1.BmpRoutingStagingReceipt{
		nil,
		{Status: "staged"},
		{Status: "staged", Views: []*agentv1.BmpRoutingViewReference{nil}},
		{Status: "staged", Views: []*agentv1.BmpRoutingViewReference{{Generation: "foreign-generation", Afi: 1, Safi: 1}}},
		{Status: "staged", Views: []*agentv1.BmpRoutingViewReference{{Generation: "owned-generation", Afi: 3, Safi: 1}}},
		{Status: "staged", Views: []*agentv1.BmpRoutingViewReference{{Generation: "owned-generation", Afi: 1, Safi: 128}}},
		{Status: "staged", Views: []*agentv1.BmpRoutingViewReference{{Generation: "owned-generation", Afi: 1, Safi: 1}, {Generation: "owned-generation", Afi: 1, Safi: 1}}},
		{Status: "invalidated", Views: []*agentv1.BmpRoutingViewReference{{Generation: "owned-generation", Afi: 1, Safi: 1}}},
	} {
		if mask, ok := routingReceiptFamilyMask(receipt, "owned-generation"); ok || mask != 0 {
			t.Fatal("partial, foreign or inconsistent receipt retained cohort metadata", mask)
		}
	}
}
