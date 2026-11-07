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
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type routingSelectorsCapture struct {
	stages   []*agentv1.BmpRoutingPeerUp
	messages []*agentv1.BmpRoutingMessage
}

func (*routingSelectorsCapture) Submit(context.Context, []entity.Observation) (int, int, error) {
	return 0, 0, nil
}
func (c *routingSelectorsCapture) StageRoutingPeer(_ context.Context, request *agentv1.BmpRoutingPeerUp) (*agentv1.BmpRoutingStagingReceipt, error) {
	c.stages = append(c.stages, proto.Clone(request).(*agentv1.BmpRoutingPeerUp))
	if request.Message[39] == 99 {
		return nil, errors.New("unbound selector")
	}
	return &agentv1.BmpRoutingStagingReceipt{Status: "staged", Views: []*agentv1.BmpRoutingViewReference{{Generation: request.ObservationId, Afi: 1, Safi: 1}}}, nil
}
func (c *routingSelectorsCapture) SubmitRoutingMessage(_ context.Context, request *agentv1.BmpRoutingMessage) (*agentv1.BmpRoutingMessageReceipt, error) {
	c.messages = append(c.messages, proto.Clone(request).(*agentv1.BmpRoutingMessage))
	return &agentv1.BmpRoutingMessageReceipt{Status: "applied", Generation: request.Generation, Sequence: request.Sequence}, nil
}

func routingBookForTest() map[uint64]bmpRoutingStreamState {
	return make(map[uint64]bmpRoutingStreamState)
}

// Protocol identity is opaque. The modeled server alone decides ownership;
// this test verifies complete transport sequencing and source-local cleanup.
func TestBMPRoutingSelectorsKeepIndependentGenerationsRefusalsAndSourceClosure(t *testing.T) {
	sink := &routingSelectorsCapture{}
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
	drive(handle, 99, true)
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
	// A real physical source closure retires every one of its known selectors.
	l.endRoutingEvidence(context.Background(), id, handle)
	peer := <-l.evidenceQueue
	before := len(sink.messages)
	l.routingStreamEvidence(context.Background(), peer, states)
	want := map[string]int64{a: 3, b: 3}
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
