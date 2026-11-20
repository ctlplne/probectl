// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/opendata"
)

func TestPublicASPathProjectionKeepsTheActualPredecessorWithinOneEpoch(t *testing.T) {
	clock := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	original := opendata.PublicMRTReceipt{Source: "routeviews", Collector: "route-views.eqix",
		ArchiveClock: clock, SHA256: strings.Repeat("ab", 32)}
	subsequent := original
	subsequent.SHA256 = strings.Repeat("cd", 32)
	peer := bgp.PublicVisibilityPeer{Address: netip.MustParseAddr("198.51.100.2"), ASN: 64496}
	route := bgp.RoutePrefix{Prefix: netip.MustParsePrefix("192.0.2.0/24"), HasPathID: true}
	path := func(asns ...uint32) bgp.RouteASPath {
		return bgp.RouteASPath{Path: bgp.ASPathReconstruction{AS4Action: "absent",
			Segments: []bgp.ASPathSegment{{Kind: bgp.ASPathSequence, Values: asns}}}}
	}
	projection := publicASPathProjection{}
	point := bgp.PublicVisibilityCollectorPoint{Baseline: original, Latest: original, Paths: &bgp.PublicArchivePathEvidence{
		RIB: []bgp.PublicArchivePath{{Peer: bgp.MRTIndexPeer{Address: peer.Address, ASN: peer.ASN},
			Route: route, ArchiveRecord: 2, RIBSequence: 13, RecordUnixNanos: clock.UnixNano(), OriginatedUnixNanos: clock.UnixNano(),
			Path: path(64496, 64497)}}}}
	baseline := projection.advance(point)
	if len(baseline) != 1 || baseline[0].Kind != "baseline" || baseline[0].Previous != nil || baseline[0].Current == nil ||
		baseline[0].Original.RIBSequence == nil || *baseline[0].Original.RIBSequence != 13 {
		t.Fatal("RIB lost its exact baseline identity", baseline)
	}
	updatePoint := bgp.PublicVisibilityCollectorPoint{Baseline: original, Latest: subsequent, Paths: &bgp.PublicArchivePathEvidence{
		Updates: []bgp.PublicArchivePathUpdate{
			{Peer: peer, Route: route, Path: path(64496, 64497), ArchiveRecord: 3, ObservedUnixNanos: clock.UnixNano() + 1000},
			{Peer: peer, Route: route, Path: path(64496, 64497, 64497), ArchiveRecord: 4, ObservedUnixNanos: clock.UnixNano() + 2000},
			{Peer: peer, Route: route, Withdraw: true, ArchiveRecord: 4, OperationIndex: 1, ObservedUnixNanos: clock.UnixNano() + 2000},
			{Peer: peer, Route: route, Withdraw: true, ArchiveRecord: 5, ObservedUnixNanos: clock.UnixNano() + 5000},
		}}}
	events := projection.advance(updatePoint)
	if len(events) != 2 || events[0].Kind != "path_change" || events[0].Previous.Source.ArchiveRecord != 3 ||
		events[0].Current.Source.ArchiveSHA256 != subsequent.SHA256 || events[1].Kind != "withdrawal" ||
		events[1].Current != nil || events[1].Previous != events[0].Current || events[1].Original.OperationIndex != 1 {
		t.Fatal("replay, prepend and exact path withdrawal lost their chronological predecessors", events)
	}
	projection.advance(bgp.PublicVisibilityCollectorPoint{Baseline: original, Latest: subsequent})
	if afterGap := projection.advance(updatePoint); len(afterGap) != 0 {
		t.Fatal("a gap allowed a later file to reuse the old baseline", afterGap)
	}
}
