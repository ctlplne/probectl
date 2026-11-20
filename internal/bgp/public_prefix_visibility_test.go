// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestPublicPrefixVisibilityCountsDistinctEligiblePeersAcrossWithdrawals(t *testing.T) {
	peerA := PublicVisibilityPeer{netip.MustParseAddr("198.51.100.1"), 64496}
	peerB := PublicVisibilityPeer{netip.MustParseAddr("198.51.100.2"), 64497}
	partial := PublicVisibilityPeer{netip.MustParseAddr("198.51.100.3"), 64498}
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	at := time.Unix(1_700_000_000, 0).UTC()
	pathA := RoutePrefix{Prefix: prefix, PathID: 0, HasPathID: true}
	pathB := RoutePrefix{Prefix: prefix, PathID: 1, HasPathID: true}
	pathC := RoutePrefix{Prefix: prefix}
	known := RouteASPath{Path: ASPathReconstruction{Segments: []ASPathSegment{{Kind: 2, Values: []uint32{64496, 64500}}}}}
	set := RouteASPath{Path: ASPathReconstruction{Segments: []ASPathSegment{{Kind: 1, Values: []uint32{64501, 64502}}}}}
	roster := map[PublicVisibilityPeer]bool{peerA: true, peerB: true, partial: false}
	projection := newPrefixVisibilityProjection(prefix, at, 2)
	projection.retain(peerA, pathA, publicVisibilityOrigins(known))
	projection.retain(peerA, pathB, publicVisibilityOrigins(known))
	projection.retain(peerB, pathC, publicVisibilityOrigins(set))
	series := PublicVisibilityCollector{next: at, cadence: time.Minute,
		projections: map[netip.Prefix]*PrefixVisibilityProjection{prefix: projection}}
	point := projection.Point()
	if !point.Available || point.EligiblePeers != 2 || point.VisiblePeers != 2 || point.AmbiguousPeers != 1 ||
		!slices.Equal(point.Origins, []PublicVisibilityOrigin{{64500, 1}, {64501, 1}, {64502, 1}}) {
		t.Fatalf("the baseline double-counted a path or silently resolved an origin set: %+v", point)
	}
	for i, tc := range []struct {
		peer    PublicVisibilityPeer
		route   RoutePrefix
		visible int
	}{
		{peerA, pathA, 2},
		{peerA, pathB, 1},
		{peerB, pathC, 0},
	} {
		from := at.Add(time.Duration(i) * time.Minute)
		to := from.Add(time.Minute)
		interval := publicVisibilityInterval{remaining: 4096, window: from, through: to,
			rosters: [2]map[PublicVisibilityPeer]bool{roster, roster}, projections: series.projections}
		for _, update := range []MRTUpdate{
			{ObservedUnixNanos: from.UnixNano(), PeerAddress: tc.peer.Address, PeerASN: tc.peer.ASN,
				Groups: []RoutingChangeGroup{{Family: RouteFamily{1, 1}, Withdrawn: []RoutePrefix{tc.route}}}},
			{ObservedUnixNanos: from.UnixNano(), PeerAddress: partial.Address, PeerASN: partial.ASN, Path: known,
				Groups: []RoutingChangeGroup{{Family: RouteFamily{1, 1}, Announced: []RoutePrefix{pathC}}}},
		} {
			if err := interval.stage(t.Context(), update); err != nil {
				t.Fatal(err)
			}
		}
		interval.commit()
		point = projection.Point()
		if !point.Available || point.EligiblePeers != 2 || point.VisiblePeers != tc.visible || !point.Through.Equal(to) {
			t.Fatalf("withdrawal %d changed the eligible cohort or lost the observed source clock: %+v", i, point)
		}
	}
	series.next = at.Add(3 * time.Minute)
	series.MarkGap()
	point = projection.Point()
	if point.Available || len(point.Origins) != 0 || !point.Through.Equal(at.Add(3*time.Minute)) {
		t.Fatalf("missing interval was reported as a complete zero: %+v", point)
	}
	interval := publicVisibilityInterval{window: at.Add(3 * time.Minute), through: at.Add(4 * time.Minute), projections: series.projections}
	interval.commit()
	if projection.Point().Available {
		t.Fatal("a late interval reopened an invalidated baseline")
	}
}

func TestPublicVisibilityArchiveKeepsOnlyBoundedNonoverlappingRollover(t *testing.T) {
	start := time.Unix(1_700_001_000, 0).UTC()
	end := start.Add(15 * time.Minute)
	interval := publicVisibilityInterval{window: start, through: end}
	rollover := end.Add(167487 * time.Microsecond)
	if err := interval.stage(t.Context(), MRTUpdate{ObservedUnixNanos: rollover.UnixNano()}); err != nil || !interval.latest.Equal(rollover) {
		t.Fatal("published rollover clock was discarded or rounded", interval.latest, err)
	}
	if err := interval.stage(t.Context(), MRTUpdate{ObservedUnixNanos: end.Add(time.Second).UnixNano()}); err == nil {
		t.Fatal("an unbounded rollover was accepted")
	}
	interval = publicVisibilityInterval{window: end, through: end.Add(15 * time.Minute), continuityFloor: rollover}
	if err := interval.stage(t.Context(), MRTUpdate{ObservedUnixNanos: end.Add(100 * time.Millisecond).UnixNano()}); err == nil {
		t.Fatal("a following file reordered already accepted source clocks")
	}
	if err := interval.stage(t.Context(), MRTUpdate{ObservedUnixNanos: end.Add(200 * time.Millisecond).UnixNano()}); err != nil {
		t.Fatal("a contiguous following file was refused", err)
	}
}
