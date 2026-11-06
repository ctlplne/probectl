// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"
)

// DecodeRoutingLifecycle accepts a complete source statistics frame or Peer
// Down bound to the retained peer. Unknown statistics counters remain opaque;
// their complete TLV framing and declared count must still match. Local timers
// and an idle socket cannot manufacture a fresh source observation.
func DecodeRoutingLifecycle(ctx context.Context, raw []byte, peer PeerUp, budget PeerMessageBudget) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || int64(len(raw)) > budget.MemoryBytes/8 || int64(len(raw)) > budget.WorkUnits/4 {
		return false, ErrBMPPeerUpBudget
	}
	const offset = bmpCommonHeaderLen + bmpPeerHeaderLen
	if len(raw) < offset+1 || raw[0] != bmpVersion || uint64(binary.BigEndian.Uint32(raw[1:5])) != uint64(len(raw)) {
		return false, errBMPSourceRoute
	}
	header, err := ParseBMPRouteViewHeader(raw[bmpCommonHeaderLen:offset])
	if err != nil || !sameBMPRoutePeer(header, peer.Header) {
		return false, errBMPSourceRoute
	}
	if raw[5] == 2 {
		_, err := parseBMPPeerDown(ctx, raw, budget)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	if raw[5] != 1 || len(raw) < offset+4 {
		return false, errBMPSourceRoute
	}
	count := binary.BigEndian.Uint32(raw[offset : offset+4])
	remaining := raw[offset+4:]
	if count == 0 || uint64(count) > uint64(len(remaining)/4) {
		return false, errBMPSourceRoute
	}
	for range count {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if len(remaining) < 4 {
			return false, errBMPSourceRoute
		}
		size := int(binary.BigEndian.Uint16(remaining[2:4]))
		if size > len(remaining)-4 || !validRoutingStatistic(binary.BigEndian.Uint16(remaining[:2]), size) {
			return false, errBMPSourceRoute
		}
		remaining = remaining[4+size:]
	}
	if len(remaining) != 0 {
		return false, errBMPSourceRoute
	}
	return false, nil
}

// RFC7854 section4.2 specifies the complete numeric encodings. Unknown
// non-reserved counters stay opaque for protocol extension, never inferred.
func validRoutingStatistic(kind uint16, size int) bool {
	switch kind {
	case 0, 1, 2, 3, 4, 5, 6, 11, 12, 13:
		return size == 4
	case 7, 8:
		return size == 8
	case 9, 10:
		return size == 11
	case 65535:
		return false
	default:
		return true
	}
}
