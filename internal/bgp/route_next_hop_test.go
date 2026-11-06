// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"errors"
	"testing"
)

func nextHopOpenForTest(afi uint16, extended, fourAS bool) []byte {
	caps := []byte{1, 4, byte(afi >> 8), byte(afi), 0, 1}
	if extended {
		caps = append(caps, 5, 6, 0, 1, 0, 1, 0, 2)
	}
	if fourAS {
		caps = append(caps, 65, 4, 255, 255, 255, 255)
	}
	return routeOpenForTest(caps, false)
}

func TestBMPNextHopEncodingFollowsReceiverAndWireFamily(t *testing.T) {
	for _, tc := range []struct {
		name           string
		family         uint16
		sent, received bool
		fourAS         bool
		view           BMPRouteView
		length         int
		want           uint16
	}{
		{"inbound-extended", 1, true, false, false, BMPAdjRIBInPrePolicy, 16, 2},
		{"inbound-post-policy", 1, true, false, false, BMPAdjRIBInPostPolicy, 32, 2},
		{"outbound-extended", 1, false, true, false, BMPAdjRIBOutPrePolicy, 16, 2},
		{"outbound-post-policy", 1, false, true, false, BMPAdjRIBOutPostPolicy, 32, 2},
		{"ipv4-wire", 1, false, false, false, BMPAdjRIBInPrePolicy, 4, 1},
		{"ipv6-wire", 2, false, false, false, BMPAdjRIBInPrePolicy, 16, 2},
		{"ipv6-link-local-wire", 2, false, false, false, BMPAdjRIBOutPostPolicy, 32, 2},
		{"capability-does-not-force-ipv6", 1, true, true, false, BMPAdjRIBInPrePolicy, 4, 1},
		{"loc-rib", 1, true, true, true, BMPLocRIB, 16, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sent := nextHopOpenForTest(tc.family, tc.sent, tc.fourAS)
			received := nextHopOpenForTest(tc.family, tc.received, tc.fourAS)
			out, err := parseBMPRouteNextHopAFI(sent, received, tc.view, RouteFamily{tc.family, 1}, tc.length)
			if err != nil || out != tc.want {
				t.Fatal("next-hop encoding lost actual receiver, explicit MP family or wire selection", out, err)
			}
		})
	}
}

func TestBMPNextHopEncodingRefusesSenderOnlyAndUnnegotiatedViews(t *testing.T) {
	plain := nextHopOpenForTest(1, false, false)
	extended := nextHopOpenForTest(1, true, false)
	t.Run("sender-capability-is-not-receiver", func(t *testing.T) {
		out, err := parseBMPRouteNextHopAFI(plain, extended, BMPAdjRIBInPrePolicy, RouteFamily{1, 1}, 16)
		if !errors.Is(err, ErrRouteCapabilities) || out != 0 {
			t.Fatal("source capability allowed an unnegotiated next-hop family", out, err)
		}
	})
	for _, tc := range []struct {
		sent, received []byte
		view           BMPRouteView
		family         RouteFamily
		length         int
	}{
		{extended, plain, BMPAdjRIBOutPostPolicy, RouteFamily{1, 1}, 16},
		{routeOpenForTest([]byte{5, 6, 0, 1, 0, 1, 0, 2}, false), extended, BMPAdjRIBInPrePolicy, RouteFamily{1, 1}, 16},
		{extended, extended, BMPAdjRIBInPrePolicy, RouteFamily{2, 1}, 16},
		{extended, extended, "", RouteFamily{1, 1}, 16},
		{extended, extended, BMPAdjRIBInPrePolicy, RouteFamily{1, 128}, 24},
		{extended, extended, BMPLocRIB, RouteFamily{1, 1}, 16},
		{nextHopOpenForTest(1, true, true), nextHopOpenForTest(1, false, true), BMPLocRIB, RouteFamily{1, 1}, 16},
		{nil, extended, BMPAdjRIBInPrePolicy, RouteFamily{1, 1}, 16},
		{extended, plain[:18], BMPAdjRIBInPrePolicy, RouteFamily{1, 1}, 16},
		{nextHopOpenForTest(2, false, false), nextHopOpenForTest(2, false, false), BMPAdjRIBInPrePolicy, RouteFamily{2, 1}, 4},
	} {
		out, err := parseBMPRouteNextHopAFI(tc.sent, tc.received, tc.view, tc.family, tc.length)
		if !errors.Is(err, ErrRouteCapabilities) || out != 0 {
			t.Fatal("incomplete source or unnegotiated MP view selected a next-hop encoding", out, err)
		}
	}
	for _, length := range []int{-1, 0, 5, 15, 24, 48} {
		out, err := parseBMPRouteNextHopAFI(extended, extended, BMPAdjRIBInPrePolicy, RouteFamily{1, 1}, length)
		if !errors.Is(err, ErrRouteCapabilities) || out != 0 {
			t.Fatal("unsupported unicast wire length guessed a next-hop family", length, out, err)
		}
	}
	for _, caps := range [][]byte{{5, 0}, {5, 5, 0, 1, 0, 1, 0}, {5, 6, 0, 1, 1, 1, 0, 2}} {
		caps = append([]byte{1, 4, 0, 1, 0, 1}, caps...)
		sent := routeOpenForTest(caps, false)
		out, err := parseBMPRouteNextHopAFI(sent, plain, BMPAdjRIBInPrePolicy, RouteFamily{1, 1}, 16)
		if !errors.Is(err, ErrRouteCapabilities) || out != 0 {
			t.Fatal("malformed or wrong full SAFI capability authorized an encoding", out, err)
		}
	}
}
