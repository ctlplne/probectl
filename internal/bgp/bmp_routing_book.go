// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

// DefaultBMPRoutingStateBytes admits retained stream metadata, not route
// counts. Wire bodies remain in the separate bounded transport queue. This
// budget can be raised for deployments with larger complete source manifests.
const DefaultBMPRoutingStateBytes int64 = 64 << 20

// This protocol selector is opaque and never supplies canonical authority.
// Only the receiver's current tenant-owned operator assignment can do that.
type bmpRoutingSelector struct {
	distinguisher [8]byte
	identifier    [4]byte
}

func bmpSelector(header BMPRouteViewHeader) bmpRoutingSelector {
	return bmpRoutingSelector{distinguisher: header.Distinguisher, identifier: header.BGPIdentifier.As4()}
}

// Worker-owned accounting covers the key, map buckets, retained state, identity
// strings and two generation nonces. The 1 KiB fixed charge conservatively
// covers both map levels even for one selector per physical session. No wire
// message or Peer Up body is retained here.
func bmpRoutingStateCharge(state bmpRoutingStreamState) int64 {
	return 1024 + int64(len(state.source.tenantID)) + int64(len(state.source.routerAgentID)) +
		int64(len(state.source.routerSerial)) + int64(len(state.generation)) + int64(len(state.previous))
}

type bmpRoutingStreams struct {
	sessions map[uint64]map[bmpRoutingSelector]bmpRoutingStreamState
	used     int64
	limit    int64
}

func newBMPRoutingStreams(limit int64) *bmpRoutingStreams {
	return &bmpRoutingStreams{sessions: make(map[uint64]map[bmpRoutingSelector]bmpRoutingStreamState), limit: limit}
}

func (streams *bmpRoutingStreams) get(peer bmpPeerEvidence) (bmpRoutingStreamState, bool) {
	state, ok := streams.sessions[peer.sessionHandle][peer.routingSelector]
	return state, ok
}

func (streams *bmpRoutingStreams) put(peer bmpPeerEvidence, state bmpRoutingStreamState) bool {
	previous, exists := streams.get(peer)
	var oldBytes int64
	if exists {
		oldBytes = bmpRoutingStateCharge(previous)
	}
	nextBytes := bmpRoutingStateCharge(state)
	if nextBytes > streams.limit || streams.used-oldBytes > streams.limit-nextBytes {
		return false
	}
	if streams.sessions[peer.sessionHandle] == nil {
		streams.sessions[peer.sessionHandle] = make(map[bmpRoutingSelector]bmpRoutingStreamState)
	}
	streams.sessions[peer.sessionHandle][peer.routingSelector] = state
	streams.used += nextBytes - oldBytes
	return true
}

func (streams *bmpRoutingStreams) remove(peer bmpPeerEvidence) {
	if state, exists := streams.get(peer); exists {
		streams.used -= bmpRoutingStateCharge(state)
		delete(streams.sessions[peer.sessionHandle], peer.routingSelector)
		if len(streams.sessions[peer.sessionHandle]) == 0 {
			delete(streams.sessions, peer.sessionHandle)
		}
	}
}

// WithBMPRoutingStateBytes configures finite whole-state admission for this
// listener's tenant lane. Refusal is observable and never truncates a source.
func WithBMPRoutingStateBytes(bytes int64) BMPOption {
	return func(l *BMPListener) {
		if bytes > 0 {
			l.routingStateBytes = bytes
		}
	}
}

func (l *BMPListener) routingStateRefused(streams *bmpRoutingStreams) {
	drops := l.evidenceDrops.Add(1)
	if counter, ok := l.evidence.(interface{ QueueDrop() }); ok {
		counter.QueueDrop()
	}
	if drops&(drops-1) == 0 {
		l.log.Warn("bmp routing metadata admission refused; raw collection retained",
			"tenant_id", l.laneTenant, "agent_id", l.evidenceAgent,
			"retained_bytes", streams.used, "budget_bytes", streams.limit, "dropped_batches", drops)
	}
}
