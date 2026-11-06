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
	"math"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type bmpRoutingMessageWriter interface {
	SubmitRoutingMessage(context.Context, *agentv1.BmpRoutingMessage) (*agentv1.BmpRoutingMessageReceipt, error)
}

type bmpRoutingStreamState struct {
	generation string
	previous   string
	sequence   int64
	failed     bool
}

func (l *BMPListener) queueRoutingMessage(id bmpIdentity, session uint64, kind byte, payload []byte) error {
	if _, ok := l.evidence.(bmpRoutingMessageWriter); !ok || len(payload) == 0 || payload[0] != 3 {
		return nil
	}
	if kind != bmpRouteMonitoring && kind != 1 && kind != 2 {
		return nil
	}
	if len(payload) < bmpPeerHeaderLen {
		return errors.New("bgp: incomplete routing lifecycle header")
	}
	header, err := ParseBMPRouteViewHeader(payload[:bmpPeerHeaderLen])
	if err != nil {
		return err
	}
	if header.Distinguisher != ([8]byte{}) {
		return nil
	} // explicitly unbound; never resets the global generation
	message := &agentv1.BmpRoutingMessage{Heartbeat: kind == 1, SourceReset: kind == 2}
	message.Message = make([]byte, bmpCommonHeaderLen+len(payload))
	message.Message[0], message.Message[5] = bmpVersion, kind
	binary.BigEndian.PutUint32(message.Message[1:5], uint32(len(message.Message)))
	copy(message.Message[6:], payload)

	observed := l.now().UTC()
	message.ObservedUnixNanos = observed.UnixNano()
	if !l.queuePeerEvidence(bmpPeerEvidence{tenantID: id.TenantID, routerAgentID: id.AgentID, routerSerial: id.Serial,
		sessionHandle: session, observedAt: observed, routingMessage: message}) {
		return errors.New("bgp: complete routing evidence queue admission exceeded")
	}
	return nil
}

// Unlike ordinary suppressible peer hints, the stream-end marker cannot be
// dropped on a full queue. FIFO places it after every frame already admitted.
func (l *BMPListener) endRoutingEvidence(ctx context.Context, id bmpIdentity, handle uint64) {
	if _, ok := l.evidence.(bmpRoutingMessageWriter); !ok || id.TenantID != l.laneTenant {
		return
	}
	select {
	case l.evidenceQueue <- bmpPeerEvidence{tenantID: id.TenantID, routerAgentID: id.AgentID, routerSerial: id.Serial,
		sessionHandle: handle, observedAt: l.now().UTC(), routingEnd: true}:
	case <-ctx.Done():
	}
}

func (l *BMPListener) cancelRoutingSession(handle uint64) {
	l.liveMu.Lock()
	session := l.live[handle]
	if session != nil {
		session.killReason = "routing evidence stream unavailable"
	}
	l.liveMu.Unlock()
	if session != nil {
		session.cancel()
	}
}

// This map is worker-owned and has one entry per admitted live socket. No
// packet identifier can create a population of retained routing sessions.
func (l *BMPListener) routingStreamEvidence(ctx context.Context, peer bmpPeerEvidence, states map[uint64]bmpRoutingStreamState) {
	writer, ok := l.evidence.(bmpRoutingMessageWriter)
	if !ok {
		if peer.routingPeerUp != nil {
			l.stageRoutingEvidence(ctx, peer)
		}
		return
	}
	if peer.tenantID != l.laneTenant {
		return
	}
	state := states[peer.sessionHandle]
	if peer.routingEnd {
		defer delete(states, peer.sessionHandle)
	}
	if peer.routingPeerUp != nil {
		if state.failed {
			return
		}
		stager, ok := l.evidence.(bmpRoutingStager)
		if !ok {
			l.cancelRoutingSession(peer.sessionHandle)
			return
		}
		state.previous, state.generation = state.generation, peer.routingPeerUp.ObservationId
		receipt, err := stager.StageRoutingPeer(ctx, peer.routingPeerUp)
		if err != nil || receipt == nil || len(receipt.Views) == 0 {
			state.failed = true
			states[peer.sessionHandle] = state
			l.cancelRoutingSession(peer.sessionHandle)
			return
		}
		states[peer.sessionHandle] = bmpRoutingStreamState{generation: peer.routingPeerUp.ObservationId}
		return
	}
	if state.generation == "" {
		return
	}
	if state.failed && !peer.routingEnd {
		return
	}
	message := peer.routingMessage
	if peer.routingEnd {
		if state.previous != "" && state.previous != state.generation {
			_, _ = writer.SubmitRoutingMessage(ctx, &agentv1.BmpRoutingMessage{SourceReset: true, ConfiguredRef: peer.routerAgentID, OriginSerial: peer.routerSerial, Generation: state.previous, Sequence: state.sequence + 1, ObservedUnixNanos: peer.observedAt.UnixNano()})
		}
		message = &agentv1.BmpRoutingMessage{SourceReset: true, ObservedUnixNanos: peer.observedAt.UnixNano()}
	}
	if message == nil || state.sequence >= math.MaxInt64-1 {
		l.cancelRoutingSession(peer.sessionHandle)
		return
	}
	state.sequence++
	message.ConfiguredRef, message.OriginSerial, message.Generation, message.Sequence = peer.routerAgentID, peer.routerSerial, state.generation, state.sequence
	_, err := writer.SubmitRoutingMessage(ctx, message)
	if err != nil {
		state.failed = true
		l.cancelRoutingSession(peer.sessionHandle)
		l.log.Warn("bmp ordered routing evidence unavailable", "tenant_id", l.laneTenant, "agent_id", l.evidenceAgent)
	}
	states[peer.sessionHandle] = state
}

// Source-driven liveness only: no timer renews routing authority merely because
// an idle TCP socket is still locally open. The source's statistics interval
// must fit the configured lease; silence expires to the labelled fallback.
