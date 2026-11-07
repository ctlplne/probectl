// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type capturedRoutingStaging struct {
	requests chan *agentv1.BmpRoutingPeerUp
}

func (c capturedRoutingStaging) Submit(context.Context, []entity.Observation) (int, int, error) {
	return 0, 0, nil
}
func (c capturedRoutingStaging) StageRoutingPeer(_ context.Context, request *agentv1.BmpRoutingPeerUp) (*agentv1.BmpRoutingStagingReceipt, error) {
	c.requests <- proto.Clone(request).(*agentv1.BmpRoutingPeerUp)
	return &agentv1.BmpRoutingStagingReceipt{Status: "staged"}, nil
}

// Real tenant-bound TLS source socket; registry and evidence sink are modeled.
func TestBMPRoutingStagingUsesAdmittedIdentityAndCompleteOriginalPeerUp(t *testing.T) {
	proveBMPRoutingStagingCompletePeer(t, false)
}

func TestBMPRoutingMappedPeerRetainsWholeOpaqueSelectorThroughRealTLS(t *testing.T) {
	proveBMPRoutingStagingCompletePeer(t, true)
}

func proveBMPRoutingStagingCompletePeer(t *testing.T, mapped bool) {
	calls := make(chan *agentv1.BmpRoutingPeerUp, 4)
	stack := startBMPTestStack(t, WithBMPTenantLane("tenant-a", "tenant-a-lane"), WithBMPEntityEvidence("listener-auth", capturedRoutingStaging{requests: calls}))
	defer stack.stop()
	cert, key, _ := stack.issue("tenant-a", "router-a", time.Hour)
	conn, err := stack.dial(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	open := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1, 1, 4, 0, 2, 0, 1}, false)
	frame := peerUpFrameForTest(open, open, nil)
	frame[6] = 3
	if mapped {
		for j := 8; j < 16; j++ {
			frame[j] = 255
		}
	}
	clear(frame[16:32])
	clear(frame[48:68])
	before := time.Now()
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	receive := func() *agentv1.BmpRoutingPeerUp {
		t.Helper()
		select {
		case request := <-calls:
			return request
		case <-time.After(5 * time.Second):
			t.Fatal("admitted Loc-RIB Peer Up did not reach routing staging")
			return nil
		}
	}
	first := receive()
	if first.ObservationId == "" || first.ConfiguredRef != "router-a" || first.OriginSerial == "" || first.ObservedUnixNanos < before.UnixNano() || !bytes.Equal(first.Message, frame) {
		t.Fatal("routing stage lost complete frame or derived authority from a payload", first)
	}
	// An adjacent-view Peer Up does not select or reset the local routing view.
	adjacent := append([]byte(nil), frame...)
	adjacent[6] = 0
	if _, err := conn.Write(adjacent); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	second := receive()
	if second.ObservationId == first.ObservationId || !bytes.Equal(second.Message, frame) || second.ConfiguredRef != first.ConfiguredRef || second.OriginSerial != first.OriginSerial {
		t.Fatal("routing metadata reused a source event nonce or staged an adjacent peer")
	}
	foreignCert, foreignKey, _ := stack.issue("tenant-b", "router-b", time.Hour)
	foreign, err := stack.dial(foreignCert, foreignKey)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = foreign.Close() }()
	_, _ = foreign.Write(frame)
	if err := foreign.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := foreign.Read(one[:]); err == nil {
		t.Fatal("foreign routing source connection remained admitted")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("foreign routing source connection was not closed")
	}
	select {
	case <-calls:
		t.Fatal("foreign source staged routing metadata")
	default:
	}
}
