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

func mpReachValueForTest(afi uint16, hops []netip.Addr, nlri []byte) []byte {
	raw := binary.BigEndian.AppendUint16(nil, afi)
	var next []byte
	for _, hop := range hops {
		next = append(next, hop.AsSlice()...)
	}
	raw = append(raw, 1, byte(len(next)))
	raw = append(raw, next...)
	raw = append(raw, 99) // Reserved, ignored on receipt; not an SNPA count.
	return append(raw, nlri...)
}

func TestMultiprotocolRoutesKeepExplicitFamiliesHopsAndPathIdentity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		afi, hop uint16
		hops     []netip.Addr
		nlri     []byte
		addPath  bool
		prefixes []RoutePrefix
	}{
		{"ipv4", 1, 1, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, []byte{24, 198, 51, 100, 0}, false, []RoutePrefix{{Prefix: netip.MustParsePrefix("198.51.100.0/24")}, {Prefix: netip.MustParsePrefix("0.0.0.0/0")}}},
		{"ipv6", 2, 2, []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("fe80::1")}, []byte{33, 0x20, 1, 0x0d, 0xb8, 0xff}, false, []RoutePrefix{{Prefix: netip.MustParsePrefix("2001:db8:8000::/33")}}},
		{"ipv4-over-ipv6", 1, 2, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, []byte{0}, false, []RoutePrefix{{Prefix: netip.MustParsePrefix("0.0.0.0/0")}}},
		{"full-path-id", 2, 2, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, []byte{255, 255, 255, 255, 0, 0, 0, 0, 0, 0}, true, []RoutePrefix{{Prefix: netip.MustParsePrefix("::/0"), PathID: 4294967295, HasPathID: true}, {Prefix: netip.MustParsePrefix("::/0"), PathID: 0, HasPathID: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := mpReachValueForTest(tc.afi, tc.hops, tc.nlri)
			out, err := ParseMPReachRoutes(context.Background(), value, tc.hop, tc.addPath, MultiprotocolBudget{1 << 20, 1 << 20})
			if err != nil || out.Family != (RouteFamily{tc.afi, 1}) || out.NextHopAFI != tc.hop || !reflect.DeepEqual(out.NextHops, tc.hops) || !reflect.DeepEqual(out.Prefixes, tc.prefixes) {
				t.Fatal("multiprotocol reach lost source family, next-hop encoding or full path identity", out, err)
			}
			withdrawal := binary.BigEndian.AppendUint16(nil, tc.afi)
			withdrawal = append(append(withdrawal, 1), tc.nlri...)
			withdrawn, err := ParseMPUnreachRoutes(context.Background(), withdrawal, tc.addPath, MultiprotocolBudget{1 << 20, 1 << 20})
			if err != nil || withdrawn.Family != (RouteFamily{tc.afi, 1}) || !reflect.DeepEqual(withdrawn.Prefixes, tc.prefixes) {
				t.Fatal("multiprotocol withdrawal lost complete family/path identities", withdrawn, err)
			}
			clear(value)
			clear(withdrawal)
			if !reflect.DeepEqual(out.NextHops, tc.hops) || !reflect.DeepEqual(out.Prefixes, tc.prefixes) || !reflect.DeepEqual(withdrawn.Prefixes, tc.prefixes) {
				t.Fatal("input mutation changed owned multiprotocol route metadata")
			}
		})
	}
	for _, afi := range []uint16{1, 2} {
		value := []byte{0, byte(afi), 1}
		out, err := ParseMPUnreachRoutes(context.Background(), value, false, MultiprotocolBudget{1000, 1000})
		if err != nil || out.Family != (RouteFamily{afi, 1}) || out.Prefixes == nil || len(out.Prefixes) != 0 {
			t.Fatal("empty multiprotocol withdrawal lost complete family", out, err)
		}
	}
}

func TestMultiprotocolRoutesRefuseGuessedEncodingMalformedTailAndAdmission(t *testing.T) {
	budget := MultiprotocolBudget{1 << 20, 1 << 20}
	good := mpReachValueForTest(1, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, []byte{0})
	for _, value := range [][]byte{nil, {0, 1, 1}, {0, 1, 1, 4}, good[:8], mpReachValueForTest(1, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, []byte{0, 32, 1})} {
		out, err := ParseMPReachRoutes(context.Background(), value, 1, false, budget)
		if !errors.Is(err, ErrMPRouteAttributes) || !reflect.DeepEqual(out, MultiprotocolReach{}) {
			t.Fatal("malformed MP_REACH returned partial next-hop or routes", err)
		}
	}
	for _, tc := range []struct {
		value []byte
		hop   uint16
	}{
		{good, 0}, {good, 2},
		{mpReachValueForTest(1, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, []byte{0}), 1},
		{mpReachValueForTest(2, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, []byte{0}), 1},
		{mpReachValueForTest(2, []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")}, []byte{0}), 2},
		{[]byte{0, 3, 1, 4, 192, 0, 2, 1, 0, 0}, 1},
		{[]byte{0, 1, 2, 4, 192, 0, 2, 1, 0, 0}, 1},
	} {
		out, err := ParseMPReachRoutes(context.Background(), tc.value, tc.hop, false, budget)
		if !errors.Is(err, ErrMPRouteAttributes) || !reflect.DeepEqual(out, MultiprotocolReach{}) {
			t.Fatal("unnegotiated family or guessed next-hop encoding admitted routes", err)
		}
	}
	for _, value := range [][]byte{nil, {0, 2}, {0, 3, 1}, {0, 1, 2}, {0, 2, 1, 0, 128, 1}} {
		out, err := ParseMPUnreachRoutes(context.Background(), value, false, budget)
		if !errors.Is(err, ErrMPRouteAttributes) || !reflect.DeepEqual(out, MultiprotocolWithdraw{}) {
			t.Fatal("malformed MP_UNREACH returned partial withdrawals", err)
		}
	}
	for _, limited := range []MultiprotocolBudget{{0, 1000}, {1000, 0}, {128, 1000}, {191, 1000}, {1000, int64(len(good)) + 1}} {
		out, err := ParseMPReachRoutes(context.Background(), good, 1, false, limited)
		if !errors.Is(err, ErrMPRouteBudget) || !reflect.DeepEqual(out, MultiprotocolReach{}) {
			t.Fatal("unadmitted multiprotocol routes returned partial output", err)
		}
	}
	for _, which := range []string{"reach", "withdraw"} {
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		for _, ctx := range []context.Context{canceled, &peerUpCancelContext{Context: context.Background()}} {
			if which == "reach" {
				out, err := ParseMPReachRoutes(ctx, good, 1, false, budget)
				if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(out, MultiprotocolReach{}) {
					t.Fatal("canceled reachability retained a partial route", err)
				}
			} else {
				out, err := ParseMPUnreachRoutes(ctx, []byte{0, 1, 1, 0}, false, budget)
				if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(out, MultiprotocolWithdraw{}) {
					t.Fatal("canceled withdrawal retained a partial route", err)
				}
			}
		}
	}
}
