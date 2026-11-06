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
	"reflect"
	"testing"
)

func sourceRouteFrameForTest(header, update []byte) []byte {
	raw := []byte{3, 0, 0, 0, 0, 0}
	raw = append(raw, header...)
	raw = append(raw, update...)
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	return raw
}

func TestBMPSourceRouteBindsPeerButUsesActualViewEncodingAndWireClock(t *testing.T) {
	plain := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1}, false)
	extended := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1, 6, 0}, false)
	for _, opens := range [][2][]byte{{extended, plain}, {plain, extended}} {
		up := peerUpFrameForTest(opens[0], opens[1], nil)
		peer, err := parseBMPPeerUp(t.Context(), up, PeerMessageBudget{1 << 20, 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		for _, flags := range []byte{0, 0x40, 0x10, 0x50, 0x2f} {
			h := append([]byte(nil), up[6:48]...)
			h[1] = flags
			clear(h[34:42])
			raw := sourceRouteFrameForTest(h, extendedRouteFrameForTest(4097))
			got, err := parseBMPSourceRoute(t.Context(), raw, peer, UpdateFrameBudget{16 << 20, 16 << 20})
			inbound := flags&0x10 == 0
			allowed := (inbound && len(opens[0]) == len(extended)) || (!inbound && len(opens[1]) == len(extended))
			if !allowed {
				if !errors.Is(err, ErrBGPUpdateFrame) || !reflect.DeepEqual(got, sourceRouteFrame{}) {
					t.Fatal("source route used Peer Up flags instead of the actual route receiver", flags, err)
				}
				continue
			}
			want, _ := ParseBMPRouteViewHeader(h)
			if err != nil || got.Header != want || got.Header.TimestampKnown || !got.Header.Timestamp.IsZero() || len(got.Update.Attributes) != 1 {
				t.Fatal("source route lost explicit view, encoding or unknown wire timestamp", flags, err)
			}
		}
	}
}

func TestBMPSourceRouteRefusesOtherPeerMalformedEnvelopeAndPartialAdmission(t *testing.T) {
	open := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1, 6, 0}, false)
	up := peerUpFrameForTest(open, open, nil)
	peer, err := parseBMPPeerUp(t.Context(), up, PeerMessageBudget{1 << 20, 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	raw := sourceRouteFrameForTest(up[6:48], endOfRIBFrameForTest(nil, nil, nil))
	budget := UpdateFrameBudget{16 << 20, 16 << 20}
	for _, change := range []func([]byte){func(r []byte) { r[0] = 2 }, func(r []byte) { r[5] = 3 }, func(r []byte) { r[4]-- }, func(r []byte) { r[6] = 2 }, func(r []byte) { r[8] = 1 }, func(r []byte) { r[31]++ }, func(r []byte) { r[35]++ }, func(r []byte) { r[39]++ }} {
		altered := append([]byte(nil), raw...)
		change(altered)
		got, err := parseBMPSourceRoute(t.Context(), altered, peer, budget)
		if err == nil || !reflect.DeepEqual(got, sourceRouteFrame{}) {
			t.Fatal("route from another peer or malformed envelope exposed source metadata", err)
		}
	}
	got, err := parseBMPSourceRoute(t.Context(), raw, peer, budget)
	if err != nil || !got.Update.HasEndOfRIB || !got.Header.TimestampKnown {
		t.Fatal("complete owned peer marker refused", err)
	}
	for _, limited := range []UpdateFrameBudget{{0, 1 << 20}, {1 << 20, 0}, {512, 384}, {128 * int64(len(raw)), 8 * int64(len(raw))}} {
		got, err := parseBMPSourceRoute(t.Context(), raw, peer, limited)
		if !errors.Is(err, ErrBGPUpdateFrameBudget) || !reflect.DeepEqual(got, sourceRouteFrame{}) {
			t.Fatal("source route returned partially admitted data", err)
		}
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := parseBMPSourceRoute(canceled, raw, peer, budget); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, sourceRouteFrame{}) {
		t.Fatal("source route ignored cancellation", err)
	}
}
