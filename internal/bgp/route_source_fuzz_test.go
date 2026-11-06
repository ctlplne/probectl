// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
)

// Extend existing nightly targets; do not add another job or time budget.
func addRouteSourceFuzzSeeds(f *testing.F) {
	open := routeOpenForTest([]byte{65, 4, 255, 255, 255, 255, 69, 4, 0, 1, 1, 3}, true)
	up := peerUpFrameForTest(open, open, []PeerUpInformation{{3, []byte("vrf-東京")}, {3, []byte("edge")}})
	f.Add(open)
	extendedOpen := nextHopOpenForTest(1, true, true)
	f.Add(append(append([]byte(nil), extendedOpen...), extendedOpen...))
	f.Add(append(append([]byte(nil), open...), open...))
	f.Add(up)
	f.Add(append([]byte(nil), up[bmpCommonHeaderLen:bmpCommonHeaderLen+bmpPeerHeaderLen]...))
	f.Add(peerDownFrameForTest(1, peerDownNotificationForTest(), false))
	f.Add(peerDownFrameForTest(6, []byte{0, 3, 0, 1, 1, 0, 3, 0, 1, 2}, true))
	f.Add(endOfRIBFrameForTest(nil, nil, nil))
	f.Add(extendedRouteFrameForTest(65535))
	sourceOpen := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1, 6, 0}, false)
	sourceUp := peerUpFrameForTest(sourceOpen, sourceOpen, nil)
	f.Add(sourceRouteFrameForTest(sourceUp[6:48], endOfRIBFrameForTest(nil, nil, nil)))
	f.Add(endOfRIBFrameForTest(nil, []byte{0x80, 15, 3, 0, 2, 1}, nil))
	f.Add(endOfRIBFrameForTest([]byte{0}, []byte{0x40, 1, 1, 0, 0x40, 2, 0}, []byte{0}))
	f.Add([]byte{0x40, 1, 1, 0, 0x40, 2, 0})
	f.Add(mpReachValueForTest(1, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, []byte{0}))
	f.Add(mpReachValueForTest(2, []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("fe80::1")}, []byte{0}))
	f.Add([]byte{0, 2, 1, 0})
}

func fuzzRouteSourceParsers(t *testing.T, raw []byte) {
	t.Helper()
	// This is the existing BMP transport's input bound for a fuzz iteration;
	// each production parser retains its explicit whole-operation admission.
	if len(raw) > bmpMaxMessageBytes {
		return
	}
	ctx := context.Background()
	memory, work := int64(len(raw))*128+1024, int64(len(raw))*64+1024
	if out, err := ParseBMPRouteViewHeader(raw); err != nil && !reflect.DeepEqual(out, BMPRouteViewHeader{}) {
		t.Fatal("invalid route-view header exposed partial source identity")
	}
	if out, end, err := ParseBGPEndOfRIB(raw); err != nil && (end || out != (RouteFamily{})) {
		t.Fatal("invalid marker exposed a completed family")
	}
	attributes, attributeErr := ParseBGPRouteAttributes(ctx, raw, RouteAttributeBudget{memory, work})
	if attributeErr != nil && attributes != nil {
		t.Fatal("invalid attributes exposed a partial path")
	}
	if attributeErr == nil {
		for _, width := range []int{2, 4} {
			if out, err := reconstructRouteASPath(ctx, attributes, width, ASPathParseBudget{memory, work}); err != nil && !reflect.DeepEqual(out, RouteASPath{}) {
				t.Fatal("invalid attribute interpretation exposed a partial AS path")
			}
		}
	}
	if out, err := parseBGPUpdateFrame(ctx, raw, UpdateFrameBudget{memory, work}); err != nil && !reflect.DeepEqual(out, UpdateFrame{}) {
		t.Fatal("invalid UPDATE exposed a partial route change")
	}
	open := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1, 6, 0}, false)
	fixed := PeerUp{Header: BMPRouteViewHeader{View: BMPLocRIB}, SentOpen: open, ReceivedOpen: open}
	peer, err := parseBMPPeerUp(ctx, peerUpFrameForTest(open, open, nil), PeerMessageBudget{1 << 20, 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := decodeBMPRouteChanges(ctx, raw, peer, UpdateFrameBudget{int64(len(raw))*512 + (8 << 20), int64(len(raw))*64 + (8 << 20)}); err != nil && !reflect.DeepEqual(out, sourceRouteChanges{}) {
		t.Fatal("invalid source changes exposed partial routes or interpreted fields")
	}
	if out, err := parseBMPSourceRoute(ctx, raw, peer, UpdateFrameBudget{memory + (1 << 20), work + (1 << 20)}); err != nil && !reflect.DeepEqual(out, sourceRouteFrame{}) {
		t.Fatal("invalid BMP source route exposed partial peer or frame")
	}
	if out, err := parseBMPRouteUpdateFrame(ctx, raw, fixed, UpdateFrameBudget{memory + (1 << 20), work + (1 << 20)}); err != nil && !reflect.DeepEqual(out, UpdateFrame{}) {
		t.Fatal("invalid negotiated UPDATE exposed partial frame")
	}
	for _, view := range []BMPRouteView{BMPAdjRIBInPrePolicy, BMPAdjRIBOutPostPolicy, BMPLocRIB} {
		source := PeerUp{Header: BMPRouteViewHeader{View: view}, SentOpen: raw[:len(raw)/2], ReceivedOpen: raw[len(raw)/2:]}
		if out, err := parseBMPRouteUpdateFrame(ctx, raw, source, UpdateFrameBudget{memory, work}); err != nil && !reflect.DeepEqual(out, UpdateFrame{}) {
			t.Fatal("invalid source UPDATE exposed partial frame")
		}
	}
	for _, afi := range []uint16{1, 2} {
		for _, addPath := range []bool{false, true} {
			if out, err := ParseBGPRoutePrefixes(ctx, raw, afi, addPath, RoutePrefixBudget{memory, work}); err != nil && out != nil {
				t.Fatal("invalid prefix input exposed partial routes")
			}
		}
	}
	for _, addPath := range []bool{false, true} {
		for _, nextHopAFI := range []uint16{1, 2} {
			if out, err := parseMPReachRoutes(ctx, raw, nextHopAFI, addPath, MultiprotocolBudget{memory, work}); err != nil && !reflect.DeepEqual(out, MultiprotocolReach{}) {
				t.Fatal("invalid multiprotocol reachability exposed partial next hops or routes")
			}
		}
		if out, err := parseMPUnreachRoutes(ctx, raw, addPath, MultiprotocolBudget{memory, work}); err != nil && !reflect.DeepEqual(out, MultiprotocolWithdraw{}) {
			t.Fatal("invalid multiprotocol withdrawal exposed partial routes")
		}
	}
	if out, err := parseBMPPeerUp(ctx, raw, PeerMessageBudget{memory, work}); err != nil && !reflect.DeepEqual(out, PeerUp{}) {
		t.Fatal("invalid Peer Up exposed partial source metadata")
	}
	if out, err := parseBMPPeerDown(ctx, raw, PeerMessageBudget{memory, work}); err != nil && !reflect.DeepEqual(out, PeerDown{}) {
		t.Fatal("invalid Peer Down exposed partial lifecycle metadata")
	}
	if out, err := parsePeerDownInformation(ctx, raw); err != nil && out != nil {
		t.Fatal("invalid Peer Down information exposed a partial namespace")
	}
	if out, err := parseRouteOpenCapabilities(raw); err != nil && !reflect.DeepEqual(out, routeOpenCapabilities{}) {
		t.Fatal("invalid OPEN exposed partial capabilities")
	}
	if len(raw) <= 4096 {
		capabilities := routeOpenCapabilities{families: make(map[RouteFamily]bool), mpFamilies: make(map[RouteFamily]bool), nextHops: make(map[routeNextHopCapability]bool), addPath: make(map[RouteFamily]byte)}
		seen := false
		// The private helper may accumulate until an error; its complete OPEN
		// caller above must discard that partial state rather than publish it.
		_ = capabilities.parseCapabilities(raw, &seen)
	}
	for _, view := range []BMPRouteView{BMPAdjRIBInPrePolicy, BMPAdjRIBOutPostPolicy, BMPLocRIB} {
		for _, family := range []RouteFamily{{1, 1}, {2, 1}} {
			for _, length := range []int{4, 16, 32} {
				if out, err := parseBMPRouteNextHopAFI(raw[:len(raw)/2], raw[len(raw)/2:], view, family, length); err != nil && out != 0 {
					t.Fatal("invalid source capabilities selected a next-hop address family")
				}
			}
		}
		if out, err := parseBMPRouteAddPath(raw[:len(raw)/2], raw[len(raw)/2:], view, RouteFamily{1, 1}); err != nil && out {
			t.Fatal("invalid capability negotiation selected ADD-PATH")
		}
	}
}

func fuzzStructuredASPath(t *testing.T, raw []byte) {
	t.Helper()
	if len(raw) > bmpMaxMessageBytes {
		return
	}
	ctx := context.Background()
	budget := ASPathParseBudget{int64(len(raw))*128 + 1024, int64(len(raw))*64 + 1024}
	for _, width := range []int{2, 4} {
		if out, err := ParseASPathSegments(ctx, raw, width, budget); err != nil && out != nil {
			t.Fatal("invalid structured AS path exposed partial segments")
		}
		input := ASPathAttributes{FourOctetSession: width == 4, Path: raw, AS4Path: raw[:len(raw)/2]}
		if len(raw) > 0 {
			input.AggregatorPresent, input.AS4AggregatorPresent = raw[0]&1 != 0, raw[0]&2 != 0
			input.AggregatorASN = 23456
		}
		if out, err := ReconstructASPath(ctx, input, budget); err != nil && !reflect.DeepEqual(out, ASPathReconstruction{}) {
			t.Fatal("invalid AS4 reconstruction exposed partial path semantics")
		}
	}
}
