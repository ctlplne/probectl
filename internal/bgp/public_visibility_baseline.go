// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"io"
	"net/netip"
	"time"
)

type PublicVisibilityBaselinePolicy struct {
	MinimumIPv4Routes, MinimumIPv6Routes int
	WorkingBytes                         int64
}

type PublicVisibilityPeerPopulation struct {
	Peer       MRTIndexPeer
	IPv4Routes int
	IPv6Routes int
}

type PublicVisibilityBaseline struct {
	Archive     MRTBaseline
	Peers       []PublicVisibilityPeerPopulation
	Projections map[netip.Prefix]*PrefixVisibilityProjection
	rosters     [2]map[PublicVisibilityPeer]bool
}

type visibilityBaselinePeer struct {
	seen   []uint64
	counts [2]int
}

type visibilityBaselinePath struct {
	peer   uint16
	route  RoutePrefix
	origin publicVisibilityOriginSet
}

type visibilityBaselineWork struct {
	remaining int64
	peers     []visibilityBaselinePeer
	ordinals  map[netip.Prefix]int
	selected  map[netip.Prefix][]visibilityBaselinePath
}

// ReadPublicVisibilityBaseline counts distinct prefixes from the complete
// source archive. Only paths for the locally monitored set survive reduction.
// The caller selects the archive by collector and clock independently of
// these prefixes and validates its container receipt before publication.
func ReadPublicVisibilityBaseline(ctx context.Context, reader io.Reader, archive MRTArchiveBudget,
	policy PublicVisibilityBaselinePolicy, prefixes []netip.Prefix) (PublicVisibilityBaseline, error) {
	if policy.MinimumIPv4Routes < 1 || policy.MinimumIPv6Routes < 1 || policy.WorkingBytes < 4096 ||
		int64(len(prefixes)) > policy.WorkingBytes/256 {
		return PublicVisibilityBaseline{}, ErrMRTBudget
	}
	work := visibilityBaselineWork{
		remaining: policy.WorkingBytes - int64(len(prefixes))*256,
		ordinals:  map[netip.Prefix]int{},
		selected:  make(map[netip.Prefix][]visibilityBaselinePath, len(prefixes)),
	}
	for _, prefix := range prefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
			return PublicVisibilityBaseline{}, ErrPublicVisibilityBaseline
		}
		work.selected[prefix] = nil
	}
	baseline, err := StageMRTBaseline(ctx, reader, archive, work.stage)
	if err != nil {
		return PublicVisibilityBaseline{}, err
	}
	return work.complete(ctx, baseline, policy)
}

func (work *visibilityBaselineWork) allocate(bytes int64) bool {
	if bytes < 0 || bytes > work.remaining {
		return false
	}
	work.remaining -= bytes
	return true
}

func (work *visibilityBaselineWork) stage(ctx context.Context, index MRTPeerIndex, rib MRTRIBRecord) error {
	if len(rib.Entries) == 0 {
		return ctx.Err()
	}
	if work.peers == nil {
		if !work.allocate(int64(len(index.Peers)) * 128) {
			return ErrMRTBudget
		}
		work.peers = make([]visibilityBaselinePeer, len(index.Peers))
	}
	prefix := rib.Entries[0].Route.Prefix
	ordinal, exists := work.ordinals[prefix]
	if !exists {
		if !work.allocate(128) {
			return ErrMRTBudget
		}
		ordinal = len(work.ordinals)
		work.ordinals[prefix] = ordinal
	}
	paths, selected := work.selected[prefix]
	for _, entry := range rib.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := work.count(int(entry.PeerIndex), ordinal, rib.Family); err != nil {
			return err
		}
		if selected {
			origin := publicVisibilityOrigins(entry.Path)
			if !work.allocate(128 + int64(len(origin.values))*8) {
				return ErrMRTBudget
			}
			paths = append(paths, visibilityBaselinePath{peer: entry.PeerIndex, route: entry.Route, origin: origin})
		}
	}
	if selected {
		work.selected[prefix] = paths
	}
	return nil
}

func (work *visibilityBaselineWork) count(index, ordinal int, family RouteFamily) error {
	if index >= len(work.peers) || family.AFI != 1 && family.AFI != 2 || family.SAFI != 1 {
		return ErrMRTRecord
	}
	peer := &work.peers[index]
	word := ordinal / 64
	if word >= len(peer.seen) {
		size := max(word+1, len(peer.seen)*2)
		if int64(size) > work.remaining/8 || !work.allocate(int64(size)*8) {
			return ErrMRTBudget
		}
		grown := make([]uint64, size)
		copy(grown, peer.seen)
		peer.seen = grown
	}
	bit := uint64(1) << (ordinal % 64)
	if peer.seen[word]&bit == 0 {
		peer.seen[word] |= bit
		peer.counts[family.AFI-1]++
	}
	return nil
}

func (work *visibilityBaselineWork) complete(ctx context.Context, baseline MRTBaseline,
	policy PublicVisibilityBaselinePolicy) (PublicVisibilityBaseline, error) {
	if !work.allocate(int64(len(baseline.PeerIndex.Peers)) * 192) {
		return PublicVisibilityBaseline{}, ErrMRTBudget
	}
	out := PublicVisibilityBaseline{Archive: baseline, Peers: make([]PublicVisibilityPeerPopulation, 0, len(baseline.PeerIndex.Peers)),
		Projections: make(map[netip.Prefix]*PrefixVisibilityProjection, len(work.selected))}
	populations := [2]int{}
	for index := range out.rosters {
		out.rosters[index] = make(map[PublicVisibilityPeer]bool, len(baseline.PeerIndex.Peers))
	}
	for index, peer := range baseline.PeerIndex.Peers {
		var counts [2]int
		if work.peers != nil {
			counts = work.peers[index].counts
		}
		key := visibilityPeerKey(peer)
		if _, duplicate := out.rosters[0][key]; duplicate {
			return PublicVisibilityBaseline{}, ErrPublicVisibilityBaseline
		}
		for af, minRoutes := range [2]int{policy.MinimumIPv4Routes, policy.MinimumIPv6Routes} {
			eligible := counts[af] >= minRoutes
			out.rosters[af][key] = eligible
			if eligible {
				populations[af]++
			}
		}
		out.Peers = append(out.Peers, PublicVisibilityPeerPopulation{Peer: peer, IPv4Routes: counts[0], IPv6Routes: counts[1]})
	}
	at := time.Unix(0, baseline.PeerIndex.ObservedUnixNanos)
	for prefix, paths := range work.selected {
		if err := ctx.Err(); err != nil {
			return PublicVisibilityBaseline{}, err
		}
		family := 1
		if prefix.Addr().Is4() {
			family = 0
		}
		roster := out.rosters[family]
		projection := newPrefixVisibilityProjection(prefix, at, populations[family])
		for _, path := range paths {
			peer := visibilityPeerKey(baseline.PeerIndex.Peers[path.peer])
			if roster[peer] {
				projection.retain(peer, path.route, path.origin)
			}
		}
		out.Projections[prefix] = projection
	}
	if err := ctx.Err(); err != nil {
		return PublicVisibilityBaseline{}, err
	}
	return out, nil
}

func visibilityPeerKey(peer MRTIndexPeer) PublicVisibilityPeer {
	return PublicVisibilityPeer{Address: peer.Address, ASN: peer.ASN}
}
