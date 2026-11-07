// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"reflect"
	"testing"
)

func frrRoutingProfileForTest() RoutingSourceProfile {
	return RoutingSourceProfile{Format: RoutingSourceFRRLocRIBV1, Families: []RouteFamily{{AFI: 1, SAFI: 1}, {AFI: 2, SAFI: 1}}}
}

func TestFRRRoutingProfileKeepsOriginalMetadataFamiliesAndStrictDefault(t *testing.T) {
	raw, err := hex.DecodeString(frr103LocRIBPeerUp)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), raw...)
	budget := PeerMessageBudget{MemoryBytes: 16 << 20, WorkUnits: 16 << 20}
	if peer, families, err := DecodeRoutingPeerUp(t.Context(), raw, budget); err == nil || !reflect.DeepEqual(peer, PeerUp{}) || families != nil {
		t.Fatal("strict default accepted malformed real-source capabilities")
	}
	profile := frrRoutingProfileForTest()
	peer, families, err := DecodeRoutingPeerUp(t.Context(), raw, budget, profile)
	if err != nil || !reflect.DeepEqual(families, profile.Families) || peer.SourceProfile.Format != RoutingSourceFRRLocRIBV1 {
		t.Fatal("explicit FRR source profile refused complete original metadata or lost declared families", err)
	}
	if !bytes.Equal(raw, original) || !bytes.Equal(peer.SentOpen, original[68:68+len(peer.SentOpen)]) || !bytes.Equal(peer.SentOpen, peer.ReceivedOpen) || len(peer.Information) != 1 || string(peer.Information[0].Value) != "global" {
		t.Fatal("source profile rewrote or truncated original OPEN/TLV metadata")
	}
	profile.Families[0].AFI = 999
	if peer.SourceProfile.Families[0].AFI != 1 {
		t.Fatal("source profile borrowed mutable operator family configuration")
	}
	_, _, attributes := sourceChangesFixture(t)
	hops := []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("fe80::1")}
	attributes = append(attributes, RouteAttribute{0x80, 14, mpReachValueForTest(2, hops, []byte{32, 0x20, 1, 0x0d, 0xb8})})
	frame := sourceRouteFrameForTest(raw[6:48], endOfRIBFrameForTest(nil, sourceChangesAttributesForTest(attributes), []byte{24, 203, 0, 113}))
	changes, err := DecodeRoutingChanges(t.Context(), frame, peer, UpdateFrameBudget{128 << 20, 128 << 20})
	if err != nil || len(changes.Groups) != 2 || len(changes.Groups[0].Announced) != 1 || len(changes.Groups[1].Announced) != 1 {
		t.Fatal("explicit FRR profile lost complete dual-family source routes", err)
	}
	if changes.Groups[0].Announced[0].Prefix.String() != "203.0.113.0/24" || changes.Groups[1].Announced[0].Prefix.String() != "2001:db8::/32" || !reflect.DeepEqual(changes.Groups[1].NextHops, hops) {
		t.Fatal("explicit FRR profile lost complete dual-family source routes", err)
	}
	for _, group := range changes.Groups {
		if group.EndOfRIB || group.Announced[0].HasPathID {
			t.Fatal("FRR source profile invented ADD-PATH identity or completion")
		}
	}
	for _, afi := range []uint16{1, 2} {
		var attrs []byte
		if afi == 2 {
			attrs = []byte{0x80, 15, 3, 0, 2, 1}
		}
		frame := sourceRouteFrameForTest(raw[6:48], endOfRIBFrameForTest(nil, attrs, nil))
		complete, err := DecodeRoutingChanges(t.Context(), frame, peer, UpdateFrameBudget{16 << 20, 16 << 20})
		if err != nil || len(complete.Groups) != 1 || !complete.Groups[0].EndOfRIB || complete.Groups[0].Family.AFI != afi {
			t.Fatal("explicit FRR profile lost an exclusive source End-of-RIB", afi, err)
		}
	}
	clear(raw)
	if !bytes.Equal(peer.SentOpen, original[68:68+len(peer.SentOpen)]) || string(peer.Information[0].Value) != "global" {
		t.Fatal("wire mutation changed owned profiled source metadata")
	}
}

func TestFRRRoutingProfileRefusesUnknownAmbiguousAndUnadmittedSources(t *testing.T) {
	raw, err := hex.DecodeString(frr103LocRIBPeerUp)
	if err != nil {
		t.Fatal(err)
	}
	budget := PeerMessageBudget{MemoryBytes: 16 << 20, WorkUnits: 16 << 20}
	validOpen := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1, 1, 4, 0, 2, 0, 1}, false)
	valid := peerUpFrameForTest(validOpen, validOpen, nil)
	valid[6] = 3
	clear(valid[16:32])
	clear(valid[48:68])
	for _, profile := range []RoutingSourceProfile{
		{Format: "unknown", Families: []RouteFamily{{1, 1}}},
		{Format: RoutingSourceFRRLocRIBV1},
		{Families: []RouteFamily{{1, 1}}},
		{Format: RoutingSourceFRRLocRIBV1, Families: []RouteFamily{{1, 1}, {1, 1}}},
		{Format: RoutingSourceFRRLocRIBV1, Families: []RouteFamily{{3, 1}}},
		{Format: RoutingSourceFRRLocRIBV1, Families: []RouteFamily{{1, 2}}},
	} {
		for _, raw := range [][]byte{raw, valid} {
			if peer, families, err := DecodeRoutingPeerUp(t.Context(), raw, budget, profile); err == nil || !reflect.DeepEqual(peer, PeerUp{}) || families != nil {
				t.Fatal("invalid source profile exposed partial routing metadata", profile)
			}
		}
	}
	profile := frrRoutingProfileForTest()
	open := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1, 69, 4, 0, 1, 1, 3}, false)
	addPath := peerUpFrameForTest(open, open, nil)
	addPath[6] = 3
	clear(addPath[16:32])
	clear(addPath[48:68])
	adjacent := append([]byte(nil), raw...)
	adjacent[6] = 0
	tail := append(append([]byte(nil), raw...), 0)
	binary.BigEndian.PutUint32(tail[1:5], uint32(len(tail)))
	for _, malformed := range [][]byte{addPath, adjacent, tail} {
		if peer, families, err := DecodeRoutingPeerUp(t.Context(), malformed, budget, profile); err == nil || !reflect.DeepEqual(peer, PeerUp{}) || families != nil {
			t.Fatal("profile accepted ADD-PATH, adjacent view or incomplete source tail")
		}
	}
	for _, budget := range []PeerMessageBudget{{}, {MemoryBytes: 1, WorkUnits: 1}} {
		if peer, families, err := DecodeRoutingPeerUp(t.Context(), raw, budget, profile); err == nil || !reflect.DeepEqual(peer, PeerUp{}) || families != nil {
			t.Fatal("profile bypassed whole source admission")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if peer, families, err := DecodeRoutingPeerUp(ctx, raw, budget, profile); err == nil || !reflect.DeepEqual(peer, PeerUp{}) || families != nil {
		t.Fatal("profile exposed canceled source metadata")
	}
}
