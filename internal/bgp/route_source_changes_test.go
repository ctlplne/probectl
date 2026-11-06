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
	"net/netip"
	"reflect"
	"testing"
)

func sourceChangesFixture(t *testing.T) (PeerUp, []byte, []RouteAttribute) {
	t.Helper()
	caps := []byte{65, 4, 0, 0, 0, 1, 6, 0, 1, 4, 0, 2, 0, 1, 69, 8, 0, 1, 1, 3, 0, 2, 1, 3}
	open := routeOpenForTest(caps, false)
	up := peerUpFrameForTest(open, open, nil)
	peer, err := parseBMPPeerUp(t.Context(), up, PeerMessageBudget{16 << 20, 16 << 20})
	if err != nil {
		t.Fatal(err)
	}
	attributes := []RouteAttribute{{0x40, 1, []byte{0}}, {0x40, 2, routeASSequenceForTest(4, 65001, 65001, 4294967295)}, {0x40, 3, []byte{192, 0, 2, 99}}, {0xc0, 250, []byte{9, 8, 7}}}
	return peer, up[6:48], attributes
}

func sourceChangesAttributesForTest(attributes []RouteAttribute) []byte {
	var raw []byte
	for _, attr := range attributes {
		if len(attr.Value) > 255 {
			raw = append(raw, attr.Flags|0x10, attr.Type)
			raw = binary.BigEndian.AppendUint16(raw, uint16(len(attr.Value)))
		} else {
			raw = append(raw, attr.Flags, attr.Type, byte(len(attr.Value)))
		}
		raw = append(raw, attr.Value...)
	}
	return raw
}

func TestBMPSourceChangesKeepCompleteDualFamilyPathsWithdrawalsAndAttributes(t *testing.T) {
	peer, header, attributes := sourceChangesFixture(t)
	hops := []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("fe80::1")}
	six := binary.BigEndian.AppendUint32(nil, 4294967295)
	six = append(six, 32, 0x20, 1, 0x0d, 0xb8)
	attributes = append(attributes, RouteAttribute{0x80, 14, mpReachValueForTest(2, hops, six)}, RouteAttribute{0x80, 15, append([]byte{0, 2, 1}, binary.BigEndian.AppendUint32(nil, 0)...)})
	// An IPv6 /0 after path ID zero is a real withdrawal, not an EOR.
	attributes[len(attributes)-1].Value = append(attributes[len(attributes)-1].Value, 0)
	var nlri []byte
	for i := range 5001 {
		nlri = binary.BigEndian.AppendUint32(nlri, uint32(i))
		nlri = append(nlri, 24, 10, byte(i>>8), byte(i))
	}
	withdrawn := append(binary.BigEndian.AppendUint32(nil, 4294967295), 0)
	raw := sourceRouteFrameForTest(header, endOfRIBFrameForTest(withdrawn, sourceChangesAttributesForTest(attributes), nlri))
	got, err := decodeBMPRouteChanges(t.Context(), raw, peer, UpdateFrameBudget{128 << 20, 128 << 20})
	if err != nil || len(got.Groups) != 3 || !reflect.DeepEqual(got.Attributes, attributes) || len(got.Path.Path.Segments) != 1 || !reflect.DeepEqual(got.Path.Path.Segments[0].Values, []uint32{65001, 65001, 4294967295}) {
		t.Fatal("complete source changes lost paths or original attributes", len(got.Groups), err)
	}
	first := got.Groups[0]
	if len(first.Announced) != 5001 || first.Announced[5000].PathID != 5000 || !first.Announced[0].HasPathID || first.Announced[0].PathID != 0 || first.Announced[5000].Prefix.String() != "10.19.136.0/24" || len(first.Withdrawn) != 1 || first.Withdrawn[0].PathID != 4294967295 || len(first.NextHops) != 1 || first.NextHops[0].String() != "192.0.2.99" {
		t.Fatal("complete source changes truncated legacy routes or guessed path identity", first)
	}
	if !reflect.DeepEqual(got.Groups[1].NextHops, hops) || got.Groups[1].Announced[0].PathID != 4294967295 || got.Groups[1].Announced[0].Prefix.String() != "2001:db8::/32" || got.Groups[2].Withdrawn[0].Prefix.String() != "::/0" || !got.Groups[2].Withdrawn[0].HasPathID || got.Groups[2].EndOfRIB {
		t.Fatal("source changes mixed explicit family, next hops or withdrawal with completion")
	}
	clear(raw)
	if !reflect.DeepEqual(got.Attributes, attributes) || !reflect.DeepEqual(got.Groups[1].NextHops, hops) {
		t.Fatal("input mutation changed owned source changes")
	}
}

func TestBMPSourceChangesRefuseMissingMandatoryFieldsAndLateMalformedTail(t *testing.T) {
	peer, header, attributes := sourceChangesFixture(t)
	nlri := append(binary.BigEndian.AppendUint32(nil, 1), 0)
	for _, change := range []string{"origin", "path", "next-hop", "duplicate-origin", "origin-value", "next-hop-flags", "mandatory-unknown", "late-tail", "mp-family", "mp-duplicate"} {
		t.Run(change, func(t *testing.T) {
			attrs := append([]RouteAttribute(nil), attributes...)
			tail := append([]byte(nil), nlri...)
			switch change {
			case "origin":
				attrs = attrs[1:]
			case "path":
				attrs = append(attrs[:1], attrs[2:]...)
			case "next-hop":
				attrs = append(attrs[:2], attrs[3:]...)
			case "duplicate-origin":
				attrs = append(attrs, attrs[0])
			case "origin-value":
				attrs[0].Value = []byte{3}
			case "next-hop-flags":
				attrs[2].Flags = 0x80
			case "mandatory-unknown":
				attrs = append(attrs, RouteAttribute{0x40, 251, []byte{1}})
			case "late-tail":
				tail = append(tail, 0, 0, 0, 2, 32, 10)
			case "mp-family":
				attrs = append(attrs, RouteAttribute{0x80, 15, []byte{0, 3, 1, 0}})
			case "mp-duplicate":
				attrs = append(attrs, RouteAttribute{0x80, 15, []byte{0, 2, 1, 0, 0, 0, 1, 0}}, RouteAttribute{0x80, 15, []byte{0, 2, 1, 0, 0, 0, 2, 0}})
			}
			raw := sourceRouteFrameForTest(header, endOfRIBFrameForTest(nil, sourceChangesAttributesForTest(attrs), tail))
			got, err := decodeBMPRouteChanges(t.Context(), raw, peer, UpdateFrameBudget{128 << 20, 128 << 20})
			if err == nil || !reflect.DeepEqual(got, sourceRouteChanges{}) {
				t.Fatal("invalid source changes exposed partial routing data", change, err)
			}
		})
	}
}

func TestBMPSourceChangesKeepExclusiveCompletionAndWholeAdmission(t *testing.T) {
	peer, header, _ := sourceChangesFixture(t)
	for _, attributes := range [][]byte{nil, {0x80, 15, 3, 0, 2, 1}} {
		raw := sourceRouteFrameForTest(header, endOfRIBFrameForTest(nil, attributes, nil))
		got, err := decodeBMPRouteChanges(t.Context(), raw, peer, UpdateFrameBudget{128 << 20, 128 << 20})
		if err != nil || len(got.Groups) != 1 || !got.Groups[0].EndOfRIB || len(got.Groups[0].Announced)+len(got.Groups[0].Withdrawn) != 0 {
			t.Fatal("exclusive source completion lost exact family marker", err)
		}
		for _, budget := range []UpdateFrameBudget{{0, 128 << 20}, {128 << 20, 0}, {8192, 128 << 20}} {
			got, err = decodeBMPRouteChanges(t.Context(), raw, peer, budget)
			if !errors.Is(err, ErrBGPUpdateFrameBudget) || !reflect.DeepEqual(got, sourceRouteChanges{}) {
				t.Fatal("unadmitted source changes returned partial data", err)
			}
		}
		canceled, cancel := context.WithCancel(t.Context())
		cancel()
		got, err = decodeBMPRouteChanges(canceled, raw, peer, UpdateFrameBudget{128 << 20, 128 << 20})
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, sourceRouteChanges{}) {
			t.Fatal("canceled source changes returned partial data", err)
		}
	}
	// Withdrawal-only messages need neither an invented origin nor a next hop.
	raw := sourceRouteFrameForTest(header, endOfRIBFrameForTest(append(binary.BigEndian.AppendUint32(nil, 0), 0), nil, nil))
	got, err := decodeBMPRouteChanges(t.Context(), raw, peer, UpdateFrameBudget{128 << 20, 128 << 20})
	if err != nil || len(got.Groups) != 1 || len(got.Groups[0].Withdrawn) != 1 || len(got.Groups[0].NextHops) != 0 || got.Groups[0].EndOfRIB {
		t.Fatal("withdrawal source invented attributes or completion", err)
	}
}
