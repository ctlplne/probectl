// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import "context"

// DecodePhysicalPeerDown retains the complete physical-neighbor lifecycle
// frame. It does not authorize a tenant, router or interface, and does not
// attribute an outage. In particular, reason 5 withdraws monitoring rather
// than proving session failure. Loc-RIB pseudo-peers use their separate path.
func DecodePhysicalPeerDown(ctx context.Context, raw []byte, budget PeerMessageBudget) (PeerDown, error) {
	peer, err := parseBMPPeerDown(ctx, raw, budget)
	if err != nil {
		return PeerDown{}, err
	}
	if !physicalPeerHeader(peer.Header) {
		return PeerDown{}, ErrBMPPeerDown
	}
	return peer, nil
}

func physicalPeerHeader(header BMPRouteViewHeader) bool {
	return header.PeerType == 0 && header.Flags&^byte(0xf0) == 0 && header.PeerASN != 0 && header.PeerAddress.IsValid() && !header.PeerAddress.IsUnspecified() && !header.PeerAddress.IsMulticast()
}
