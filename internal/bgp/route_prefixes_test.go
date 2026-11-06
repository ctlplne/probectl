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

func TestBGPRoutePrefixesKeepBothFamiliesPaddingAndWholeAddPathIdentity(t *testing.T) {
	cases := []struct {
		name    string
		raw     []byte
		afi     uint16
		addPath bool
		want    []BGPRoutePrefix
	}{
		{"v4-default-and-padding", []byte{0, 25, 192, 0, 2, 255}, 1, false, []BGPRoutePrefix{{Prefix: netip.MustParsePrefix("0.0.0.0/0")}, {Prefix: netip.MustParsePrefix("192.0.2.128/25")}}},
		{"v6-default-and-padding", append([]byte{0, 127}, append(netip.MustParseAddr("2001:db8::").AsSlice()[:15], 255)...), 2, false, []BGPRoutePrefix{{Prefix: netip.MustParsePrefix("::/0")}, {Prefix: netip.MustParsePrefix("2001:db8::fe/127")}}},
		{"zero-and-full-path-ids", []byte{0, 0, 0, 0, 24, 192, 0, 2, 255, 255, 255, 255, 24, 192, 0, 2}, 1, true, []BGPRoutePrefix{{netip.MustParsePrefix("192.0.2.0/24"), 0, true}, {netip.MustParsePrefix("192.0.2.0/24"), 4294967295, true}}},
		{"mapped-v6-family", append([]byte{120}, netip.MustParseAddr("::ffff:192.0.2.0").AsSlice()[:15]...), 2, false, []BGPRoutePrefix{{Prefix: netip.MustParsePrefix("::ffff:192.0.2.0/120")}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseBGPRoutePrefixes(t.Context(), tc.raw, tc.afi, tc.addPath, BGPRoutePrefixBudget{1 << 20, 1 << 20})
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatal("unicast prefixes lost full family, padding, order or ADD-PATH identity", got, err)
			}
			clear(tc.raw)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatal("unicast prefixes retained mutable input")
			}
		})
	}
	raw := []byte{}
	want := make([]BGPRoutePrefix, 5001)
	for i := range want {
		raw = binary.BigEndian.AppendUint32(raw, uint32(i))
		raw = append(raw, 24, 10, byte(i>>8), byte(i))
		want[i] = BGPRoutePrefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24), uint32(i), true}
	}
	got, err := ParseBGPRoutePrefixes(t.Context(), raw, 1, true, BGPRoutePrefixBudget{int64(len(want) * 64), int64(len(raw) * 2)})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("complete unicast prefix population was truncated under exact finite admission", len(got), err)
	}
	for _, afi := range []uint16{1, 2} {
		got, err := ParseBGPRoutePrefixes(t.Context(), nil, afi, false, BGPRoutePrefixBudget{1, 1})
		if err != nil || got == nil || len(got) != 0 {
			t.Fatal("complete empty NLRI invented routes", afi, got, err)
		}
	}
}

func TestBGPRoutePrefixesRefuseLateMalformedOrUnadmittedInput(t *testing.T) {
	valid := []byte{24, 192, 0, 2}
	for _, tc := range []struct {
		raw     []byte
		afi     uint16
		addPath bool
	}{
		{append(append([]byte(nil), valid...), 25, 192), 1, false},
		{[]byte{33}, 1, false}, {[]byte{129}, 2, false},
		{[]byte{0, 0, 0}, 1, true}, {[]byte{0, 0, 0, 0}, 1, true},
		{valid, 0, false}, {valid, 3, false},
	} {
		got, err := ParseBGPRoutePrefixes(t.Context(), tc.raw, tc.afi, tc.addPath, BGPRoutePrefixBudget{1 << 20, 1 << 20})
		if !errors.Is(err, ErrBGPRoutePrefix) || got != nil {
			t.Fatal("malformed unicast tail returned a partial route set", got, err)
		}
	}
	for _, budget := range []BGPRoutePrefixBudget{{0, 100}, {100, 0}, {63, 100}, {100, 7}} {
		got, err := ParseBGPRoutePrefixes(t.Context(), valid, 1, false, budget)
		if !errors.Is(err, ErrBGPRoutePrefixBudget) || got != nil {
			t.Fatal("unicast population escaped complete operation admission", budget, got, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := ParseBGPRoutePrefixes(ctx, valid, 1, false, BGPRoutePrefixBudget{1 << 20, 1 << 20}); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatal("canceled unicast input returned partial routes", got, err)
	}
}
