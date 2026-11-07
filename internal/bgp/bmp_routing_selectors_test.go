// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type routingSelectorsCapture struct {
	refuse   bool
	stages   []*agentv1.BmpRoutingPeerUp
	messages []*agentv1.BmpRoutingMessage
}

func (*routingSelectorsCapture) Submit(context.Context, []entity.Observation) (int, int, error) {
	return 0, 0, nil
}
func (c *routingSelectorsCapture) StageRoutingPeer(_ context.Context, request *agentv1.BmpRoutingPeerUp) (*agentv1.BmpRoutingStagingReceipt, error) {
	c.stages = append(c.stages, proto.Clone(request).(*agentv1.BmpRoutingPeerUp))
	if c.refuse && request.Message[39] == 99 {
		return nil, errors.New("unbound selector")
	}
	return &agentv1.BmpRoutingStagingReceipt{Status: "staged", Views: []*agentv1.BmpRoutingViewReference{{Generation: request.ObservationId, Afi: 1, Safi: 1}}}, nil
}
func (c *routingSelectorsCapture) SubmitRoutingMessage(_ context.Context, request *agentv1.BmpRoutingMessage) (*agentv1.BmpRoutingMessageReceipt, error) {
	c.messages = append(c.messages, proto.Clone(request).(*agentv1.BmpRoutingMessage))
	if request.SourceReset {
		return &agentv1.BmpRoutingMessageReceipt{Status: "invalidated", Generation: request.Generation, Sequence: request.Sequence}, nil
	}
	return &agentv1.BmpRoutingMessageReceipt{Status: "applied", Generation: request.Generation, Sequence: request.Sequence}, nil
}

func routingBookForTest() *bmpRoutingStreams {
	return newBMPRoutingStreams(DefaultBMPRoutingStateBytes)
}

// Protocol identity is opaque. The modeled server alone decides ownership;
// this test verifies complete transport sequencing and source-local cleanup.
func TestBMPRoutingSelectorsKeepIndependentGenerationsRefusalsAndSourceClosure(t *testing.T) {
	sink := &routingSelectorsCapture{refuse: true}
	l := NewBMPListener(nil, nil, "", nil, WithBMPTenantLane("tenant-a", "lane-a"), WithBMPEntityEvidence("listener-a", sink))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id := bmpIdentity{TenantID: "tenant-a", AgentID: "router-a", Serial: "serial-a"}
	handle := l.registerLive(&bmpLiveSession{id: id, cancel: cancel})
	other := l.registerLive(&bmpLiveSession{id: id, cancel: func() {}})
	states := routingBookForTest()
	frame := func(selector byte, up bool) []byte {
		open := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1}, false)
		raw := peerUpFrameForTest(open, open, nil)
		raw[6] = 3
		clear(raw[16:32])
		clear(raw[48:68])
		raw[39] = selector
		if !up {
			update := make([]byte, 23)
			for i := range 16 {
				update[i] = 255
			}
			update[18] = 2
			binary.BigEndian.PutUint16(update[16:18], 23)
			raw = append(raw[:48:48], update...)
			raw[5] = 0
			binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
		}
		return raw
	}
	drive := func(session uint64, selector byte, up bool) {
		t.Helper()
		raw := frame(selector, up)
		var err error
		if up {
			err = l.queueRoutingPeerUp(id, session, raw[6:])
		} else {
			err = l.queueRoutingMessage(id, session, 0, raw[6:])
		}
		if err != nil {
			t.Fatal(err)
		}
		select {
		case peer := <-l.evidenceQueue:
			l.routingStreamEvidence(context.Background(), peer, states)
		default:
			t.Fatal("admitted selector silently skipped routing transport")
		}
	}
	drive(handle, 1, true)
	a := sink.stages[len(sink.stages)-1].ObservationId
	drive(handle, 2, true)
	b := sink.stages[len(sink.stages)-1].ObservationId
	drive(other, 1, true)
	sibling := sink.stages[len(sink.stages)-1].ObservationId
	drive(handle, 1, false)
	drive(handle, 2, false)
	if len(sink.messages) != 2 || sink.messages[0].Generation != a || sink.messages[1].Generation != b || sink.messages[0].Sequence != 1 || sink.messages[1].Sequence != 1 {
		t.Fatal("routing selectors shared a generation or sequence", sink.messages)
	}
	beforeRefusal := states.used
	drive(handle, 99, true)
	if len(states.sessions[handle]) != 2 || states.used != beforeRefusal {
		t.Fatal("rejected fresh selector retained routing metadata")
	}
	if ctx.Err() != nil {
		t.Fatal("unbound selector closed raw collection")
	}
	for _, message := range sink.messages[2:] {
		if message.Generation == a || message.Generation == b || message.Generation == sibling {
			t.Fatal("unbound selector reset a known sibling generation", message)
		}
	}
	drive(handle, 1, false)
	drive(handle, 2, false)
	last := sink.messages[len(sink.messages)-2:]
	if last[0].Generation != a || last[1].Generation != b || last[0].Sequence != 2 || last[1].Sequence != 2 {
		t.Fatal("unbound selector disabled known routing streams", last)
	}
	// A selected-view Peer Down closes only its own generation. It also frees
	// local metadata, and cannot disable another selector on the same socket.
	down := append(frame(1, false)[:48:48], byte(6))
	down[5] = 2
	binary.BigEndian.PutUint32(down[1:5], uint32(len(down)))
	if err := l.queueRoutingMessage(id, handle, 2, down[6:]); err != nil {
		t.Fatal(err)
	}
	closing := <-l.evidenceQueue
	l.routingStreamEvidence(context.Background(), closing, states)
	if _, exists := states.get(closing); exists {
		t.Fatal("confirmed Peer Down retained routing selector state")
	}
	beforeClosed := len(sink.messages)
	drive(handle, 1, false)
	if len(sink.messages) != beforeClosed {
		t.Fatal("closed selector resumed without a fresh complete Peer Up")
	}
	drive(handle, 2, false)
	if message := sink.messages[len(sink.messages)-1]; message.Generation != b || message.Sequence != 3 {
		t.Fatal("Peer Down changed a sibling selector", message)
	}
	drive(handle, 1, true)
	a = sink.stages[len(sink.stages)-1].ObservationId
	drive(handle, 1, false)
	if message := sink.messages[len(sink.messages)-1]; message.Generation != a || message.Sequence != 1 {
		t.Fatal("fresh selector Peer Up failed to restart its independent sequence", message)
	}
	// A real physical source closure retires every one of its known selectors.
	l.endRoutingEvidence(context.Background(), id, handle)
	peer := <-l.evidenceQueue
	before := len(sink.messages)
	l.routingStreamEvidence(context.Background(), peer, states)
	want := map[string]int64{a: 2, b: 4}
	for _, message := range sink.messages[before:] {
		sequence, ok := want[message.Generation]
		if !ok || !message.SourceReset || message.Sequence != sequence {
			t.Fatal("source closure reset foreign generation or lost a selector", message)
		}
		delete(want, message.Generation)
	}
	if len(want) != 0 {
		t.Fatal("source closure left known routing selectors current", want)
	}
	drive(other, 1, false)
	if last := sink.messages[len(sink.messages)-1]; last.Generation != sibling || last.Sequence != 1 || last.SourceReset {
		t.Fatal("source closure changed another physical connection", last)
	}
}

func TestBMPRoutingMetadataAdmissionKeepsWholePopulationAndReclaimsSourceState(t *testing.T) {
	sink := &routingSelectorsCapture{}
	l := NewBMPListener(nil, nil, "", nil, WithBMPTenantLane("tenant-a", "lane-a"), WithBMPEntityEvidence("listener-a", sink))
	states := newBMPRoutingStreams(l.routingStateBytes)
	const population = 5001
	observed := time.Now().UTC()
	peer := func(handle uint64, index uint32) bmpPeerEvidence {
		header := BMPRouteViewHeader{BGPIdentifier: netip.AddrFrom4([4]byte{192, 0, 2, byte(index % 2)})}
		binary.BigEndian.PutUint64(header.Distinguisher[:], uint64(index))
		selector := bmpSelector(header)
		raw := make([]byte, 48)
		copy(raw[8:16], selector.distinguisher[:])
		copy(raw[36:40], selector.identifier[:])
		return bmpPeerEvidence{tenantID: "tenant-a", routerAgentID: "router-a", routerSerial: "serial-a", sessionHandle: handle, routingSelector: selector, observedAt: observed,
			routingPeerUp: &agentv1.BmpRoutingPeerUp{ObservationId: fmt.Sprintf("%08x-%04x-4111-8111-111111111111", index, handle), Message: raw}}
	}
	for i := uint32(1); i <= population; i++ {
		l.routingStreamEvidence(context.Background(), peer(1, i), states)
	}
	if len(states.sessions[1]) != population || len(sink.stages) != population || states.used <= 0 || states.used >= l.routingStateBytes {
		t.Fatal("complete selector population clipped to a former count or lost metadata accounting", len(states.sessions[1]), len(sink.stages), states.used)
	}
	for _, state := range states.sessions[1] {
		if state.source.routingPeerUp != nil || state.source.routingMessage != nil {
			t.Fatal("retained stream metadata borrowed a complete wire payload")
		}
	}
	t.Log("complete routing metadata admission bytes", states.used, "selectors", population)
	// Other physical sources with identical selectors have independent state.
	l.routingStreamEvidence(context.Background(), peer(2, 1), states)
	sibling, _ := states.get(peer(2, 1))
	siblingCharge := bmpRoutingStateCharge(sibling)
	states.limit = states.used
	before := states.used
	l.routingStreamEvidence(context.Background(), peer(1, population+1), states)
	if states.used != before || len(sink.stages) != population+1 || len(states.sessions[1]) != population || l.evidenceDrops.Load() != 1 {
		t.Fatal("unadmitted selector staged partial state or changed known routing population")
	}
	// A larger configured byte profile admits the same complete source, with
	// no changed workload, truncated definition or weakened assertion.
	expanded := peer(1, population+1)
	charge := bmpRoutingStateCharge(bmpRoutingStreamState{generation: expanded.routingPeerUp.ObservationId, source: bmpPeerEvidence{tenantID: expanded.tenantID, routerAgentID: expanded.routerAgentID, routerSerial: expanded.routerSerial}})
	states.limit += charge
	l.routingStreamEvidence(context.Background(), expanded, states)
	if len(states.sessions[1]) != population+1 || len(sink.stages) != population+2 || states.used != before+charge {
		t.Fatal("increased byte profile did not admit the complete original selector")
	}
	// Replacing a known generation also needs admission for both nonces until
	// the receiver confirms replacement. Refusal must retire only the old one.
	replacement := peer(1, 1)
	replacement.routingPeerUp.ObservationId = "aaaaaaaa-1111-4111-8111-111111111111"
	resets := len(sink.messages)
	l.routingStreamEvidence(context.Background(), replacement, states)
	failed, _ := states.get(replacement)
	if !failed.failed || len(sink.stages) != population+2 || len(sink.messages) != resets+1 || !sink.messages[resets].SourceReset || sink.messages[resets].Generation == replacement.routingPeerUp.ObservationId {
		t.Fatal("unadmitted replacement retained old current authority or reset an unattempted generation")
	}
	// A source reset frees every selector and byte charge, preserving siblings.
	l.routingStreamEvidence(context.Background(), bmpPeerEvidence{tenantID: "tenant-a", routerAgentID: "router-a", routerSerial: "serial-a", sessionHandle: 1, routingEnd: true, observedAt: observed}, states)
	if _, exists := states.sessions[1]; exists || len(states.sessions[2]) != 1 || states.used != siblingCharge {
		t.Fatal("source closure lost sibling accounting or retained selector metadata", states.used, siblingCharge)
	}
	l.routingStreamEvidence(context.Background(), bmpPeerEvidence{tenantID: "tenant-a", routerAgentID: "router-a", routerSerial: "serial-a", sessionHandle: 2, routingEnd: true, observedAt: observed}, states)
	if states.used != 0 || len(states.sessions) != 0 {
		t.Fatal("complete source closure leaked retained stream metadata", states.used)
	}
	configured := NewBMPListener(nil, nil, "", nil, WithBMPRoutingStateBytes(DefaultBMPRoutingStateBytes*2))
	if configured.routingStateBytes != DefaultBMPRoutingStateBytes*2 {
		t.Fatal("routing byte profile option was ignored")
	}
}

func TestBMPRoutingSourceLossRetiresAllSelectorsAfterSocketDeregistration(t *testing.T) {
	sink := &routingSelectorsCapture{}
	l := NewBMPListener(nil, nil, "", nil, WithBMPTenantLane("tenant-a", "lane-a"), WithBMPEntityEvidence("listener-a", sink))
	rawCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id := bmpIdentity{TenantID: "tenant-a", AgentID: "router-a", Serial: "serial-a"}
	handle := l.registerLive(&bmpLiveSession{id: id, cancel: cancel})
	other := l.registerLive(&bmpLiveSession{id: id, cancel: func() {}})
	states := routingBookForTest()
	observed := time.Now().UTC()
	for index := byte(1); index <= 3; index++ {
		peer := bmpPeerEvidence{tenantID: id.TenantID, routerAgentID: id.AgentID, routerSerial: id.Serial, sessionHandle: handle,
			routingSelector: bmpRoutingSelector{identifier: [4]byte{192, 0, 2, index}}, routingLoss: l.routingSessionLoss(handle), observedAt: observed}
		if !states.put(peer, bmpRoutingStreamState{source: peer, generation: fmt.Sprintf("owned-%d", index), sequence: int64(index)}) {
			t.Fatal("known stream metadata admission refused")
		}
	}
	sibling := bmpPeerEvidence{tenantID: id.TenantID, routerAgentID: id.AgentID, routerSerial: id.Serial, sessionHandle: other, routingLoss: l.routingSessionLoss(other)}
	if !states.put(sibling, bmpRoutingStreamState{source: sibling, generation: "sibling", sequence: 11}) {
		t.Fatal("sibling stream metadata admission refused")
	}
	l.loseRoutingEvidence(handle)
	l.deregisterLive(handle)
	l.retireLostRoutingStreams(context.Background(), states)
	if len(sink.messages) != 3 {
		t.Fatal("physical loss left known routing selectors current", len(sink.messages))
	}
	seen := map[string]bool{}
	for _, message := range sink.messages {
		if !message.SourceReset || message.Generation == "sibling" || seen[message.Generation] || message.OriginSerial != id.Serial || message.ConfiguredRef != id.AgentID {
			t.Fatal("physical loss reset unrelated authority or repeated a selector", message)
		}
		seen[message.Generation] = true
	}
	for _, state := range states.sessions[handle] {
		if !state.failed {
			t.Fatal("physical loss retained a writable routing selector")
		}
	}
	if state, _ := states.get(sibling); state.failed || state.sequence != 11 {
		t.Fatal("physical loss changed another socket's routing state")
	}
	if rawCtx.Err() != nil {
		t.Fatal("evidence loss canceled raw BGP collection")
	}
}
