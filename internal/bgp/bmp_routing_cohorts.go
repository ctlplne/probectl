// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"math"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func routingReceiptFamilyMask(receipt *agentv1.BmpRoutingStagingReceipt, generation string) (uint8, bool) {
	if receipt == nil || receipt.Status != "staged" && receipt.Status != "replayed" || len(receipt.Views) == 0 || len(receipt.Views) > 2 {
		return 0, false
	}
	var mask uint8
	for _, view := range receipt.Views {
		if view == nil || view.Generation != generation || view.Afi < 1 || view.Afi > 2 || view.Safi != 1 {
			return 0, false
		}
		bit := uint8(1 << (view.Afi - 1))
		if mask&bit != 0 {
			return 0, false
		}
		mask |= bit
	}
	return mask, true
}

func routingCohortSource(peer bmpPeerEvidence) bmpPeerEvidence {
	return bmpPeerEvidence{tenantID: peer.tenantID, routerAgentID: peer.routerAgentID, routerSerial: peer.routerSerial, sessionHandle: peer.sessionHandle, routingLoss: peer.routingLoss, routingSelector: peer.routingSelector}
}

func (l *BMPListener) retireMatchingCohorts(ctx context.Context, writer bmpRoutingMessageWriter, peer bmpPeerEvidence, states *bmpRoutingStreams, mask uint8, remove bool) {
	for _, selected := range states.peers(peer) {
		state, _ := states.get(selected)
		if mask != 0 && state.familyMask != 0 && mask&state.familyMask == 0 {
			continue
		}
		if !state.failed {
			l.retireRoutingStream(ctx, writer, selected, &state)
		}
		if remove {
			states.remove(selected)
		} else {
			states.put(selected, state)
		}
	}
}

func (l *BMPListener) stageRoutingCohort(ctx context.Context, writer bmpRoutingMessageWriter, peer bmpPeerEvidence, states *bmpRoutingStreams) {
	if peer.routingLoss != nil && peer.routingLoss.Load() {
		l.retireMatchingCohorts(ctx, writer, peer, states, 0, false)
		return
	}
	stager, ok := l.evidence.(bmpRoutingStager)
	if !ok {
		l.retireMatchingCohorts(ctx, writer, peer, states, 0, false)
		return
	}
	selected, previous, existed := states.resolve(peer)
	attempt := bmpRoutingStreamState{source: routingCohortSource(selected), generation: peer.routingPeerUp.ObservationId}
	if existed {
		attempt.familyMask = previous.familyMask
		attempt.previous, attempt.previousSequence = previous.generation, previous.sequence
	}
	// The single worker cannot change its book during this synchronous RPC.
	// Account the full attempted/previous nonce before asking the receiver to stage.
	if _, admitted := states.admit(selected, attempt); !admitted {
		l.routingStateRefused(states)
		l.retireMatchingCohorts(ctx, writer, peer, states, 0, false)
		return
	}
	receipt, err := stager.StageRoutingPeer(ctx, peer.routingPeerUp)
	mask, valid := routingReceiptFamilyMask(receipt, attempt.generation)
	if err != nil || !valid {
		if existed {
			l.retireRoutingStream(ctx, writer, selected, &attempt)
			states.put(selected, attempt)
		} else {
			l.retireMatchingCohorts(ctx, writer, peer, states, 0, false)
			l.retireRoutingStream(ctx, writer, selected, &attempt)
		}
		l.log.Warn("bmp routing staging unavailable; raw collection retained", "tenant_id", l.laneTenant, "agent_id", l.evidenceAgent)
		return
	}
	if existed && receipt.Status == "replayed" && previous.generation == attempt.generation && previous.familyMask == mask {
		return
	}
	l.retireMatchingCohorts(ctx, writer, peer, states, mask, true)
	peer.routingSelector.cohort = mask
	current := bmpRoutingStreamState{familyMask: mask, generation: attempt.generation, source: routingCohortSource(peer)}
	if !states.put(peer, current) {
		// A disjoint receipt may need another slot rather than replacing the old
		// one used by preflight. Refuse its whole private generation, preserving
		// the independently retained cohort and every other source.
		l.routingStateRefused(states)
		l.retireRoutingStream(ctx, writer, peer, &current)
	}
}

func (l *BMPListener) dispatchRoutingCohorts(ctx context.Context, writer bmpRoutingMessageWriter, peer bmpPeerEvidence, states *bmpRoutingStreams) {
	peers := states.peers(peer)
	if len(peers) == 0 {
		return
	}
	if peer.routingLoss != nil && peer.routingLoss.Load() {
		l.retireMatchingCohorts(ctx, writer, peer, states, 0, false)
		return
	}
	var mask uint8
	if len(peers) > 1 && peer.routingMessage != nil && !peer.routingMessage.Heartbeat && !peer.routingMessage.SourceReset {
		var err error
		mask, err = parseRoutingMessageFamilyMask(ctx, peer.routingMessage.Message, UpdateFrameBudget{128 * bmpMaxMessageBytes, 8 * bmpMaxMessageBytes})
		if err != nil {
			l.retireMatchingCohorts(ctx, writer, peer, states, 0, false)
			return
		}
	}
	covered := false
	for _, selected := range peers {
		state, _ := states.get(selected)
		if mask != 0 && state.familyMask != 0 && mask&state.familyMask != mask {
			continue
		}
		covered = true
		if state.failed {
			continue
		}
		l.sendRoutingCohortMessage(ctx, writer, selected, states, state)
	}
	if !covered {
		l.retireMatchingCohorts(ctx, writer, peer, states, 0, false)
	}
}

func (l *BMPListener) sendRoutingCohortMessage(ctx context.Context, writer bmpRoutingMessageWriter, peer bmpPeerEvidence, states *bmpRoutingStreams, state bmpRoutingStreamState) {
	if state.generation == "" {
		return
	}
	if peer.routingMessage == nil || state.sequence >= math.MaxInt64-1 {
		l.retireRoutingStream(ctx, writer, peer, &state)
		states.put(peer, state)
		return
	}
	message := proto.Clone(peer.routingMessage).(*agentv1.BmpRoutingMessage)
	state.sequence++
	message.ConfiguredRef, message.OriginSerial, message.Generation, message.Sequence = peer.routerAgentID, peer.routerSerial, state.generation, state.sequence
	_, err := writer.SubmitRoutingMessage(ctx, message)
	if err != nil {
		l.retireRoutingStream(ctx, writer, peer, &state)
		l.log.Warn("bmp ordered routing evidence unavailable", "tenant_id", l.laneTenant, "agent_id", l.evidenceAgent)
	}
	if message.SourceReset && err == nil {
		states.remove(peer)
	} else {
		states.put(peer, state)
	}
}
