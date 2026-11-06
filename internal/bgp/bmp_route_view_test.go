// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func routeViewHeaderForTest(kind, flags byte, address string) []byte {
	raw := make([]byte, bmpPeerHeaderLen)
	raw[0], raw[1] = kind, flags
	if kind != 0 {
		copy(raw[2:10], []byte{255, 254, 253, 252, 251, 250, 249, 248})
	}
	if address != "" {
		ip := netip.MustParseAddr(address).As16()
		copy(raw[10:26], ip[:])
		if flags&0x80 == 0 {
			clear(raw[10:22])
		}
	}
	binary.BigEndian.PutUint32(raw[26:30], 4294967295)
	copy(raw[30:34], []byte{192, 0, 2, 1})
	binary.BigEndian.PutUint32(raw[34:38], 1700000000)
	binary.BigEndian.PutUint32(raw[38:42], 999999)
	return raw
}

func TestBMPRouteViewKeepsSelectedAdjacentEncodingAndSourceClockDistinct(t *testing.T) {
	cases := []struct {
		name        string
		kind, flags byte
		address     string
		view        BMPRouteView
		width       int
		filtered    bool
	}{
		{"input-pre", 0, 0, "192.0.2.2", BMPAdjRIBInPrePolicy, 4, false},
		{"input-post-legacy", 1, 0x60, "192.0.2.2", BMPAdjRIBInPostPolicy, 2, false},
		{"output-pre", 2, 0x10, "192.0.2.2", BMPAdjRIBOutPrePolicy, 4, false},
		{"output-post-legacy-ipv6", 1, 0xf0, "2001:db8::2", BMPAdjRIBOutPostPolicy, 2, false},
		{"input-ipv6-reserved", 2, 0x8f, "2001:db8::2", BMPAdjRIBInPrePolicy, 4, false},
		{"loc-rib", 3, 0, "", BMPLocRIB, 4, false},
		{"loc-rib-filtered-reserved", 3, 0xff, "", BMPLocRIB, 4, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := routeViewHeaderForTest(tc.kind, tc.flags, tc.address)
			got, err := ParseBMPRouteViewHeader(raw)
			if err != nil || got.View != tc.view || got.ASNWidth != tc.width || got.Filtered != tc.filtered || got.PeerType != tc.kind || got.Flags != tc.flags || got.PeerASN != 4294967295 || got.BGPIdentifier.String() != "192.0.2.1" || !got.TimestampKnown || !got.Timestamp.Equal(time.Unix(1700000000, 999999000).UTC()) {
				t.Fatal("BMP route view changed selected-vs-adjacent identity, encoding or source clock", got, err)
			}
			if tc.address == "" && got.PeerAddress.IsValid() || tc.address != "" && got.PeerAddress.String() != tc.address {
				t.Fatal("BMP view invented a peer address or address family", got.PeerAddress)
			}
			if tc.kind != 0 && got.Distinguisher != [8]byte{255, 254, 253, 252, 251, 250, 249, 248} {
				t.Fatal("BMP view discarded its complete namespace")
			}
			before := got
			clear(raw)
			if !reflect.DeepEqual(before, got) {
				t.Fatal("BMP view retained mutable wire data")
			}
		})
	}
	raw := routeViewHeaderForTest(3, 0, "")
	clear(raw[34:42])
	got, err := ParseBMPRouteViewHeader(raw)
	if err != nil || got.TimestampKnown || !got.Timestamp.IsZero() {
		t.Fatal("unavailable BMP source clock became a current observation", got, err)
	}
}

func TestBMPRouteViewRefusesMalformedIdentityWithoutPartialMetadata(t *testing.T) {
	base := routeViewHeaderForTest(0, 0, "192.0.2.2")
	variants := [][]byte{nil, base[:41], append(append([]byte(nil), base...), 0)}
	for _, mutate := range []func([]byte){
		func(raw []byte) { raw[0] = 4 },
		func(raw []byte) { raw[2] = 1 },
		func(raw []byte) { raw[10] = 1 },
		func(raw []byte) { binary.BigEndian.PutUint32(raw[38:42], 1000000) },
		func(raw []byte) { raw[0] = 3 },
	} {
		raw := append([]byte(nil), base...)
		mutate(raw)
		variants = append(variants, raw)
	}
	for _, raw := range variants {
		got, err := ParseBMPRouteViewHeader(raw)
		if !errors.Is(err, ErrBMPRouteViewHeader) || !reflect.DeepEqual(got, BMPRouteViewHeader{}) {
			t.Fatal("malformed BMP view published partial source identity", got, err)
		}
	}
}
