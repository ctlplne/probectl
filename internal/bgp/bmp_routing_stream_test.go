// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type capturedRoutingStream struct {
	capturedRoutingStaging
	messages chan *agentv1.BmpRoutingMessage
}

func (c capturedRoutingStream) StageRoutingPeer(ctx context.Context, request *agentv1.BmpRoutingPeerUp) (*agentv1.BmpRoutingStagingReceipt, error) {
	_, err := c.capturedRoutingStaging.StageRoutingPeer(ctx, request)
	return &agentv1.BmpRoutingStagingReceipt{Status: "staged", Views: []*agentv1.BmpRoutingViewReference{{Id: "22222222-2222-4222-8222-222222222222", Generation: request.ObservationId, Afi: 1, Safi: 1}}}, err
}
func (c capturedRoutingStream) SubmitRoutingMessage(_ context.Context, request *agentv1.BmpRoutingMessage) (*agentv1.BmpRoutingMessageReceipt, error) {
	c.messages <- proto.Clone(request).(*agentv1.BmpRoutingMessage)
	return &agentv1.BmpRoutingMessageReceipt{Status: "applied", Generation: request.Generation, Sequence: request.Sequence}, nil
}

// Actual tenant-bound source TLS; registry and restricted RPC sink are modeled.
func TestBMPRoutingWholeStreamKeepsFIFOAndResetsOnSourceClosure(t *testing.T) {
	stages := make(chan *agentv1.BmpRoutingPeerUp, 4)
	messages := make(chan *agentv1.BmpRoutingMessage, 8)
	sink := capturedRoutingStream{capturedRoutingStaging{stages}, messages}
	stack := startBMPTestStack(t, WithBMPTenantLane("tenant-a", "tenant-a-lane"), WithBMPEntityEvidence("listener-auth", sink))
	defer stack.stop()
	cert, key, _ := stack.issue("tenant-a", "router-a", time.Hour)
	conn, err := stack.dial(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	open := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1}, false)
	up := peerUpFrameForTest(open, open, nil)
	up[6] = 3
	clear(up[16:32])
	clear(up[48:68])
	if _, err := conn.Write(up); err != nil {
		t.Fatal(err)
	}
	var stage *agentv1.BmpRoutingPeerUp
	select {
	case stage = <-stages:
	case <-time.After(5 * time.Second):
		t.Fatal("routing source failed to stage")
	}
	update := make([]byte, 23)
	for i := range 16 {
		update[i] = 255
	}
	update[18] = 2
	binary.BigEndian.PutUint16(update[16:18], uint16(len(update)))
	raw := append(append([]byte(nil), up[:48]...), update...)
	raw[5] = 0
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	for range 2 {
		if _, err := conn.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	for seq := int64(1); seq <= 2; seq++ {
		select {
		case message := <-messages:
			if message.Sequence != seq || message.Generation != stage.ObservationId || message.ConfiguredRef != stage.ConfiguredRef || message.OriginSerial != stage.OriginSerial || message.Heartbeat || message.SourceReset || !bytes.Equal(message.Message, raw) {
				t.Fatal("routing stream lost complete source frame, identity or FIFO", message)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("routing frame failed to reach ordered evidence")
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-messages:
		if !message.SourceReset || message.Sequence != 3 || message.Generation != stage.ObservationId || len(message.Message) != 0 {
			t.Fatal("source closure did not retire its exact routing generation", message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("source closure lost its ordered reset")
	}
}
