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
)

var errBMPSourceRoute = errors.New("bgp: route monitoring does not match its complete peer source")

type sourceRouteFrame struct {
	Header BMPRouteViewHeader
	Update UpdateFrame
}

// parseBMPSourceRoute binds one complete Route Monitoring message to its
// complete Peer Up metadata. This is protocol identity, never tenant/router
// authority. Wire time remains explicitly known/unknown and cannot replace a
// separately authenticated collector observation or current assignment epoch.
func parseBMPSourceRoute(ctx context.Context, raw []byte, peer PeerUp, budget UpdateFrameBudget) (sourceRouteFrame, error) {
	if err := ctx.Err(); err != nil {
		return sourceRouteFrame{}, err
	}
	if budget.MemoryBytes <= 512 || budget.WorkUnits <= 384 || int64(len(raw)) > budget.MemoryBytes/128 || int64(len(raw)) > budget.WorkUnits/8 {
		return sourceRouteFrame{}, ErrBGPUpdateFrameBudget
	}
	const offset = bmpCommonHeaderLen + bmpPeerHeaderLen
	if len(raw) < offset+bgpHeaderLen+4 || raw[0] != bmpVersion || raw[5] != bmpRouteMonitoring || uint64(binary.BigEndian.Uint32(raw[1:5])) != uint64(len(raw)) {
		return sourceRouteFrame{}, errBMPSourceRoute
	}
	route, err := ParseBMPRouteViewHeader(raw[bmpCommonHeaderLen:offset])
	if err != nil {
		return sourceRouteFrame{}, err
	}
	if !sameBMPRoutePeer(route, peer.Header) {
		return sourceRouteFrame{}, errBMPSourceRoute
	}
	// RFC8671 Peer Up/Down headers do not select an inbound/outbound view.
	// Likewise policy and ASN wire encoding belong to the actual RM header.
	// Retain the OPENs, but let this route's view choose receiving capabilities.
	source := peer
	source.Header = route
	budget.MemoryBytes -= 512
	budget.WorkUnits -= 384
	update, err := parseBMPRouteUpdateFrame(ctx, raw[offset:], source, budget)
	if err != nil {
		return sourceRouteFrame{}, err
	}
	return sourceRouteFrame{Header: route, Update: update}, nil
}

func sameBMPRoutePeer(route, peer BMPRouteViewHeader) bool {
	if route.PeerType != peer.PeerType || route.Distinguisher != peer.Distinguisher || route.PeerAddress != peer.PeerAddress || route.PeerASN != peer.PeerASN || route.BGPIdentifier != peer.BGPIdentifier {
		return false
	}
	if route.PeerType == 3 {
		return route.Filtered == peer.Filtered
	}
	return true
}
