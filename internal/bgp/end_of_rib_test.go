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

func endOfRIBFrameForTest(withdrawn, attributes, nlri []byte) []byte {
	raw := make([]byte, bgpHeaderLen)
	for i := range 16 {
		raw[i] = 255
	}
	raw[18] = 2
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(withdrawn)))
	raw = append(raw, withdrawn...)
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(attributes)))
	raw = append(raw, attributes...)
	raw = append(raw, nlri...)
	binary.BigEndian.PutUint16(raw[16:18], uint16(len(raw)))
	return raw
}

func TestBGPEndOfRIBKeepsExplicitWholeFrameAndFamily(t *testing.T) {
	for _, tc := range []struct {
		name string
		attr []byte
		want RouteFamily
	}{
		{"legacy-v4", nil, RouteFamily{1, 1}},
		{"ipv6", []byte{0x80, 15, 3, 0, 2, 1}, RouteFamily{2, 1}},
		{"extended-length", []byte{0x90, 15, 0, 3, 0, 2, 1}, RouteFamily{2, 1}},
		{"reserved-flags", []byte{0x8f, 15, 3, 0, 2, 1}, RouteFamily{2, 1}},
		{"full-family-values", []byte{0x80, 15, 3, 255, 255, 255}, RouteFamily{65535, 255}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, end, err := ParseBGPEndOfRIB(endOfRIBFrameForTest(nil, tc.attr, nil))
			if err != nil || !end || got != tc.want {
				t.Fatal("whole End-of-RIB marker lost its exact family", got, end, err)
			}
		})
	}
}

func TestBGPEndOfRIBRefusesRouteCarryingAndMalformedCompleteness(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		withdrawn, attr, nlri []byte
	}{
		{"legacy-default-route", nil, nil, []byte{0}},
		{"withdrawn-default-route", []byte{0}, nil, nil},
		{"multiprotocol-default-route", nil, []byte{0x80, 15, 4, 0, 2, 1, 0}, nil},
		{"multiprotocol-with-legacy-nlri", nil, []byte{0x80, 15, 3, 0, 2, 1}, []byte{0}},
		{"multiple-attributes", nil, []byte{0x80, 15, 3, 0, 2, 1, 0x40, 1, 1, 0}, nil},
		{"different-attribute", nil, []byte{0x40, 1, 1, 0}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, end, err := ParseBGPEndOfRIB(endOfRIBFrameForTest(tc.withdrawn, tc.attr, tc.nlri))
			if err != nil || end || got != (RouteFamily{}) {
				t.Fatal("route-carrying update manufactured End-of-RIB completeness", got, end, err)
			}
		})
	}
	good := endOfRIBFrameForTest(nil, nil, nil)
	variants := [][]byte{nil, good[:18], endOfRIBFrameForTest(nil, []byte{0x80}, nil), endOfRIBFrameForTest(nil, []byte{0x80, 15, 2, 0, 2}, nil), endOfRIBFrameForTest(nil, []byte{0xa0, 15, 3, 0, 2, 1}, nil), endOfRIBFrameForTest(nil, []byte{0x80, 15, 4, 0, 2, 1}, nil)}
	for _, mutate := range []func([]byte){
		func(raw []byte) { raw[0] = 0 },
		func(raw []byte) { binary.BigEndian.PutUint16(raw[16:18], uint16(len(raw)-1)) },
		func(raw []byte) { binary.BigEndian.PutUint16(raw[19:21], 65535) },
		func(raw []byte) { binary.BigEndian.PutUint16(raw[21:23], 65535) },
	} {
		raw := append([]byte(nil), good...)
		mutate(raw)
		variants = append(variants, raw)
	}
	for _, raw := range variants {
		got, end, err := ParseBGPEndOfRIB(raw)
		if !errors.Is(err, ErrBGPRouteFrame) || end || got != (RouteFamily{}) {
			t.Fatal("malformed BGP frame acquired route completeness", got, end, err)
		}
	}
}
