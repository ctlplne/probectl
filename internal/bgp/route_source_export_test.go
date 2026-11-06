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

// SourcePeerUpForTest exposes only the decoder to the external real-router
// fixture. Production callers still need the authenticated source service.
func SourcePeerUpForTest(ctx context.Context, raw []byte, budget PeerMessageBudget) (PeerUp, error) {
	return parseBMPPeerUp(ctx, raw, budget)
}

// SourceRouteForTest is a test-only bridge for actual pinned FRR wire input.
func SourceRouteForTest(ctx context.Context, raw []byte, peer PeerUp, budget UpdateFrameBudget) (sourceRouteFrame, error) {
	return parseBMPSourceRoute(ctx, raw, peer, budget)
}

// SourceLegacyPrefixesForTest preserves the actual source's ADD-PATH encoding.
func SourceLegacyPrefixesForTest(ctx context.Context, frame sourceRouteFrame, peer PeerUp) ([]RoutePrefix, error) {
	add, err := parseBMPRouteAddPath(peer.SentOpen, peer.ReceivedOpen, frame.Header.View, RouteFamily{AFI: 1, SAFI: 1})
	if err != nil {
		return nil, err
	}
	return ParseBGPRoutePrefixes(ctx, frame.Update.ReachableIPv4, 1, add, RoutePrefixBudget{MemoryBytes: 16 << 20, WorkUnits: 16 << 20})
}

// SourceMPReachForTest decodes the complete actual family/next-hop/NLRI tuple.
func SourceMPReachForTest(ctx context.Context, value []byte, frame sourceRouteFrame, peer PeerUp) (MultiprotocolReach, error) {
	if len(value) < 4 {
		return MultiprotocolReach{}, ErrMPRouteAttributes
	}
	family := RouteFamily{AFI: binary.BigEndian.Uint16(value[:2]), SAFI: value[2]}
	add, err := parseBMPRouteAddPath(peer.SentOpen, peer.ReceivedOpen, frame.Header.View, family)
	if err != nil {
		return MultiprotocolReach{}, err
	}
	nextHop, err := parseBMPRouteNextHopAFI(peer.SentOpen, peer.ReceivedOpen, frame.Header.View, family, int(value[3]))
	if err != nil {
		return MultiprotocolReach{}, err
	}
	return parseMPReachRoutes(ctx, value, nextHop, add, MultiprotocolBudget{MemoryBytes: 16 << 20, WorkUnits: 16 << 20})
}
