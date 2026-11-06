// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"encoding/binary"
	"errors"
	"testing"
)

func routeOpenForTest(capabilities []byte, extended bool) []byte {
	raw := make([]byte, 29)
	for i := range 16 {
		raw[i] = 255
	}
	raw[18], raw[19] = 1, 4
	binary.BigEndian.PutUint16(raw[20:22], 65001)
	binary.BigEndian.PutUint16(raw[22:24], 90)
	copy(raw[24:28], []byte{192, 0, 2, 1})
	if extended {
		// The old length is deliberately not 255: RFC9072 ignores it.
		raw[28] = 1
		raw = append(raw, 255)
		raw = binary.BigEndian.AppendUint16(raw, uint16(len(capabilities)+3))
		raw = append(raw, 2)
		raw = binary.BigEndian.AppendUint16(raw, uint16(len(capabilities)))
	} else if len(capabilities) != 0 {
		raw[28] = byte(len(capabilities) + 2)
		raw = append(raw, 2, byte(len(capabilities)))
	}
	raw = append(raw, capabilities...)
	binary.BigEndian.PutUint16(raw[16:18], uint16(len(raw)))
	return raw
}

func TestBMPRouteAddPathKeepsDirectionAndLocRIBEncoding(t *testing.T) {
	for _, tc := range []struct {
		name          string
		local, remote byte
		view          BMPRouteView
		want          bool
	}{
		{"inbound-direction", 1, 2, BMPAdjRIBInPrePolicy, true},
		{"inbound-post-policy", 1, 2, BMPAdjRIBInPostPolicy, true},
		{"outbound-direction", 2, 1, BMPAdjRIBOutPrePolicy, true},
		{"outbound-post-policy", 2, 1, BMPAdjRIBOutPostPolicy, true},
		{"both-directions", 3, 3, BMPAdjRIBInPrePolicy, true},
		{"one-sided-receive", 1, 1, BMPAdjRIBInPrePolicy, false},
		{"one-sided-send", 2, 2, BMPAdjRIBOutPrePolicy, false},
		{"opposite-direction", 2, 1, BMPAdjRIBInPrePolicy, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local := routeOpenForTest([]byte{69, 4, 0, 1, 1, tc.local}, false)
			remote := routeOpenForTest([]byte{69, 4, 0, 1, 1, tc.remote}, false)
			got, err := parseBMPRouteAddPath(local, remote, tc.view, RouteFamily{1, 1})
			if err != nil || got != tc.want {
				t.Fatal("ADD-PATH negotiation guessed path identifiers from one endpoint or the wrong direction", got, err)
			}
		})
	}
	for _, family := range []RouteFamily{{2, 1}, {65535, 255}} {
		// Loc-RIB uses presence even for receive-only intent, with the full
		// family and four-octet ASN capability preserved in fabricated OPENs.
		caps := []byte{1, 4, byte(family.AFI >> 8), byte(family.AFI), 99, family.SAFI, 65, 4, 255, 255, 255, 255, 69, 4, byte(family.AFI >> 8), byte(family.AFI), family.SAFI, 1}
		for range 300 {
			caps = append(caps, 200, 0) // Unrecognized capabilities are ignored.
		}
		open := routeOpenForTest(caps, true)
		got, err := parseBMPRouteAddPath(open, open, BMPLocRIB, family)
		if err != nil || !got {
			t.Fatal("Loc-RIB lost complete extended OPEN, family or presence-based encoding", family, got, err)
		}
	}
	plain := routeOpenForTest(nil, false)
	got, err := parseBMPRouteAddPath(plain, plain, BMPAdjRIBInPrePolicy, RouteFamily{1, 1})
	if err != nil || got {
		t.Fatal("complete ordinary OPEN invented ADD-PATH", got, err)
	}
}

func TestBMPRouteAddPathRefusesIncompleteAndAmbiguousCapabilities(t *testing.T) {
	good := routeOpenForTest([]byte{69, 4, 0, 1, 1, 3}, false)
	variants := [][]byte{nil, good[:18], good[:len(good)-1]}
	for _, capabilities := range [][]byte{
		{69, 0}, {69, 3, 0, 1, 1}, {69, 4, 0, 1, 1, 0}, {69, 4, 0, 1, 1, 4},
		{69, 8, 0, 1, 1, 1, 0, 1, 1, 2},
		{69, 4, 0, 1, 1, 3, 69, 4, 0, 1, 1, 3},
		{65, 3, 0, 0, 1}, {65, 4, 0, 0, 0, 1, 65, 4, 0, 0, 0, 2},
		{1, 3, 0, 2, 1}, {69, 4, 0, 1, 1, 3, 200, 20},
	} {
		variants = append(variants, routeOpenForTest(capabilities, false))
	}
	for _, mutate := range []func([]byte){
		func(raw []byte) { raw[0] = 0 },
		func(raw []byte) { raw[18] = 2 },
		func(raw []byte) { raw[19] = 3 },
		func(raw []byte) { raw[28]++ },
		func(raw []byte) { raw[30]++ },
		func(raw []byte) { binary.BigEndian.PutUint16(raw[16:18], uint16(len(raw)-1)) },
	} {
		raw := append([]byte(nil), good...)
		mutate(raw)
		variants = append(variants, raw)
	}
	extended := routeOpenForTest([]byte{69, 4, 0, 1, 1, 3}, true)
	extended[31]++
	variants = append(variants, extended, append([]byte(nil), extended[:31]...))
	for _, raw := range variants {
		for _, opens := range [][2][]byte{{raw, good}, {good, raw}} {
			got, err := parseBMPRouteAddPath(opens[0], opens[1], BMPAdjRIBInPrePolicy, RouteFamily{1, 1})
			if !errors.Is(err, ErrRouteCapabilities) || got {
				t.Fatal("incomplete or ambiguous capabilities selected a route encoding", got, err)
			}
		}
	}
	for _, tc := range []struct {
		sent, received []byte
		view           BMPRouteView
		family         RouteFamily
	}{
		{good, good, "", RouteFamily{1, 1}},
		{good, good, BMPAdjRIBInPrePolicy, RouteFamily{2, 1}},
		{good, good, BMPLocRIB, RouteFamily{1, 1}}, // No mandatory four-AS capability.
		{routeOpenForTest([]byte{65, 4, 0, 0, 0, 1, 69, 4, 0, 1, 1, 3}, false), good, BMPLocRIB, RouteFamily{1, 1}},
	} {
		got, err := parseBMPRouteAddPath(tc.sent, tc.received, tc.view, tc.family)
		if !errors.Is(err, ErrRouteCapabilities) || got {
			t.Fatal("unnegotiated family or fabricated-view mismatch selected an encoding", got, err)
		}
	}
}
