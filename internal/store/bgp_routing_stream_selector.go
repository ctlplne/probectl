// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import "encoding/hex"

// The authenticated source and current stored generation have already resolved
// canonical ownership. Packet selectors can only reject that selection, never
// replace it or grant another tenant, context, router or serializer profile.
func routingStreamSelectorMatches(source BGPRoutingSource, peer *BGPRoutingPeer) error {
	if peer == nil {
		return nil
	} // payload-free authenticated generation reset
	if peer.Type != 3 || !peer.BGPIdentifier.Is4() {
		return ErrBGPRoutingView
	}
	if source.routingSelection == nil {
		if peer.Distinguisher != ([8]byte{}) {
			return ErrBGPRoutingView
		}
		return nil
	}
	binding := source.routingSelection.Binding
	if binding.Distinguisher != hex.EncodeToString(peer.Distinguisher[:]) || binding.BGPIdentifier != peer.BGPIdentifier.String() {
		return ErrBGPRoutingView
	}
	return nil
}
