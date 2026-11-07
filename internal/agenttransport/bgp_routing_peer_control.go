// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"net/netip"

	"github.com/ctlplne/probectl/internal/store"
)

// This fixed key can only scope invalidation of already authorized state. It
// does not decode an OPEN, choose a tenant/context, or create a routing view.
// The current non-global fence applies even when the OPEN body is malformed.
func routingRefusalPeer(message []byte) (*store.BGPRoutingPeer, bool) {
	if len(message) >= 7 && message[6] != 3 {
		return nil, true
	}
	if len(message) < 16 {
		return nil, false
	}
	for _, value := range message[8:16] {
		if value != 0 {
			return nil, true
		}
	}
	if len(message) < 48 {
		return nil, false
	}
	return &store.BGPRoutingPeer{Type: 3, BGPIdentifier: netip.AddrFrom4([4]byte(message[36:40]))}, false
}
