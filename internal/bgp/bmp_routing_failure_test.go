// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"google.golang.org/protobuf/proto"
)

type routingFailureCapture struct {
	stages               int
	messages             []*agentv1.BmpRoutingMessage
	stageErr, messageErr error
}

func (c *routingFailureCapture) Submit(context.Context, []entity.Observation) (int, int, error) {
	return 0, 0, nil
}
func (c *routingFailureCapture) StageRoutingPeer(context.Context, *agentv1.BmpRoutingPeerUp) (*agentv1.BmpRoutingStagingReceipt, error) {
	c.stages++
	return nil, c.stageErr
}
func (c *routingFailureCapture) SubmitRoutingMessage(_ context.Context, message *agentv1.BmpRoutingMessage) (*agentv1.BmpRoutingMessageReceipt, error) {
	c.messages = append(c.messages, proto.Clone(message).(*agentv1.BmpRoutingMessage))
	if !message.SourceReset {
		return nil, c.messageErr
	}
	return &agentv1.BmpRoutingMessageReceipt{Status: "invalidated", Generation: message.Generation, Sequence: message.Sequence}, nil
}

// Modeled RPC responses exercise the listener's exact synchronous loss path.
func TestBMPRoutingEvidenceFailureKeepsRawSessionAndRetiresOnlyOwnedGenerations(t *testing.T) {
	for _, stageFailure := range []bool{true, false} {
		name := "message"
		if stageFailure {
			name = "staging"
		}
		t.Run(name, func(t *testing.T) {
			sink := &routingFailureCapture{stageErr: errors.New("staging refused"), messageErr: errors.New("message refused")}
			l := NewBMPListener(nil, nil, "", nil, WithBMPTenantLane("tenant-a", "lane-a"), WithBMPEntityEvidence("listener-a", sink))
			rawCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			handle := l.registerLive(&bmpLiveSession{cancel: cancel})
			states := map[uint64]bmpRoutingStreamState{handle: {generation: "old-generation", sequence: 7}, handle + 1: {generation: "sibling", sequence: 11}}
			peer := bmpPeerEvidence{tenantID: "tenant-a", routerAgentID: "router-a", routerSerial: "serial-a", sessionHandle: handle, observedAt: time.Now()}
			if stageFailure {
				peer.routingPeerUp = &agentv1.BmpRoutingPeerUp{ObservationId: "attempted-generation"}
			} else {
				peer.routingMessage = &agentv1.BmpRoutingMessage{Message: []byte{1, 2, 3}}
			}
			// A foreign lane must not even submit a reset for a locally known handle.
			foreign := peer
			foreign.tenantID = "tenant-b"
			l.routingStreamEvidence(context.Background(), foreign, states)
			if sink.stages != 0 || len(sink.messages) != 0 {
				t.Fatal("foreign tenant touched routing evidence")
			}
			l.routingStreamEvidence(context.Background(), peer, states)
			if rawCtx.Err() != nil {
				t.Fatal("routing evidence failure cancelled raw BGP collection")
			}
			want := map[string]int64{"old-generation": 8}
			if stageFailure {
				want["attempted-generation"] = 1
			} else {
				want["old-generation"] = 9
			}
			for _, msg := range sink.messages {
				if !msg.SourceReset {
					continue
				}
				sequence, ok := want[msg.Generation]
				if !ok || sequence != msg.Sequence || msg.ConfiguredRef != "router-a" || msg.OriginSerial != "serial-a" || len(msg.Message) != 0 || msg.ObservedUnixNanos != peer.observedAt.UnixNano() {
					t.Fatal("routing refusal reset unrelated authority or lost exact sequence", msg)
				}
				delete(want, msg.Generation)
			}
			if len(want) != 0 {
				t.Fatal("routing evidence failure retained an owned current generation", want)
			}
			if !states[handle].failed || states[handle+1].generation != "sibling" || states[handle+1].sequence != 11 {
				t.Fatal("routing refusal changed sibling stream or retained failed state")
			}
			before := len(sink.messages)
			peer.routingPeerUp = nil
			peer.routingMessage = &agentv1.BmpRoutingMessage{Message: []byte{4}}
			l.routingStreamEvidence(context.Background(), peer, states)
			if len(sink.messages) != before {
				t.Fatal("failed evidence stream resumed without a complete source restart")
			}
		})
	}
}

func TestBMPRoutingQueueLossKeepsRawSessionAndInvalidatesBeforePendingData(t *testing.T) {
	sink := &routingFailureCapture{}
	l := NewBMPListener(nil, nil, "", nil, WithBMPTenantLane("tenant-a", "lane-a"), WithBMPEntityEvidence("listener-a", sink))
	l.evidenceQueue = make(chan bmpPeerEvidence, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id := bmpIdentity{TenantID: "tenant-a", AgentID: "router-a", Serial: "serial-a"}
	handle := l.registerLive(&bmpLiveSession{id: id, cancel: cancel})
	raw := buildBMPRouteMonitoring(64500, "192.0.2.7", []uint32{64500}, "203.0.113.0/24", time.Now())
	raw[6] = 3
	clear(raw[16:32])
	if err := l.queueRoutingMessage(id, handle, 0, raw[6:]); err != nil {
		t.Fatal(err)
	}
	if err := l.queueRoutingMessage(id, handle, 0, raw[6:]); err != nil {
		t.Fatal("routing queue overflow interrupted raw BGP collection", err)
	}
	pending := <-l.evidenceQueue
	states := map[uint64]bmpRoutingStreamState{handle: {generation: "owned", sequence: 4}}
	l.routingStreamEvidence(context.Background(), pending, states)
	if ctx.Err() != nil {
		t.Fatal("routing queue overflow cancelled raw source")
	}
	if len(sink.messages) != 1 || !sink.messages[0].SourceReset || sink.messages[0].Generation != "owned" || sink.messages[0].Sequence != 5 || !states[handle].failed {
		t.Fatal("lost routing frame allowed queued data to retain a current generation", sink.messages)
	}
	if err := l.queueRoutingMessage(id, handle, 0, raw[6:]); err != nil || len(l.evidenceQueue) != 0 {
		t.Fatal("broken routing stream admitted more data or stopped raw collection", err)
	}
}

func TestBMPRoutingLossWakesIdleEvidenceWorkerWithoutClosingRawSource(t *testing.T) {
	stages := make(chan *agentv1.BmpRoutingPeerUp, 1)
	messages := make(chan *agentv1.BmpRoutingMessage, 2)
	sink := capturedRoutingStream{capturedRoutingStaging{stages}, messages}
	l := NewBMPListener(nil, nil, "", nil, WithBMPTenantLane("tenant-a", "lane-a"), WithBMPEntityEvidence("listener-a", sink))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); l.evidenceLoop(ctx) }()
	defer func() { cancel(); <-done }()
	rawCtx, rawCancel := context.WithCancel(context.Background())
	defer rawCancel()
	id := bmpIdentity{TenantID: "tenant-a", AgentID: "router-a", Serial: "serial-a"}
	handle := l.registerLive(&bmpLiveSession{id: id, cancel: rawCancel})
	open := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1}, false)
	raw := peerUpFrameForTest(open, open, nil)
	raw[6] = 3
	clear(raw[16:32])
	clear(raw[48:68])
	if err := l.queueRoutingPeerUp(id, handle, raw[6:]); err != nil {
		t.Fatal(err)
	}
	var up *agentv1.BmpRoutingPeerUp
	select {
	case up = <-stages:
	case <-time.After(5 * time.Second):
		t.Fatal("source failed to stage before loss")
	}
	l.loseRoutingEvidence(handle)
	// No subsequent packet or stream-end event wakes the evidence worker.
	select {
	case reset := <-messages:
		if !reset.SourceReset || reset.Generation != up.ObservationId || reset.Sequence != 1 || reset.ConfiguredRef != id.AgentID || reset.OriginSerial != id.Serial {
			t.Fatal("idle loss reset another routing generation", reset)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("idle evidence worker kept current routing authority after local loss")
	}
	if rawCtx.Err() != nil {
		t.Fatal("idle evidence loss cancelled raw collection")
	}
}
