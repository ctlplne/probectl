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
	"net/netip"
	"testing"
)

func TestPhysicalPeerDownKeepsWholeReasonAndRefusesPseudoPeers(t *testing.T) {
	budget := PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20}
	for _, tc := range []struct {
		reason byte
		data   []byte
	}{
		{1, peerDownNotificationForTest()}, {2, []byte{255, 255}}, {3, peerDownNotificationForTest()}, {4, nil}, {5, nil},
	} {
		raw := peerDownFrameForTest(tc.reason, tc.data, false)
		original := append([]byte(nil), raw...)
		got, err := DecodePhysicalPeerDown(t.Context(), raw, budget)
		if err != nil || got.Reason != tc.reason || got.Header.PeerType != 0 || !bytes.Equal(raw, original) {
			t.Fatal("whole physical frame or distinct reason was lost", tc.reason, err)
		}
		if tc.reason == 1 || tc.reason == 3 {
			clear(raw)
			if !bytes.Equal(got.Notification, tc.data) {
				t.Fatal("notification borrowed mutable input")
			}
		}
	}
	for _, mutate := range []func([]byte) []byte{
		func(raw []byte) []byte { raw[6] = 3; clear(raw[16:32]); return raw },
		func(raw []byte) []byte { raw[6] = 1; return raw },
		func(raw []byte) []byte { raw[7] |= 4; return raw },
		func(raw []byte) []byte { binary.BigEndian.PutUint32(raw[32:36], 0); return raw },
		func(raw []byte) []byte {
			address := netip.MustParseAddr("ff02::1").As16()
			raw[7] |= 0x80
			copy(raw[16:32], address[:])
			return raw
		},
		func(raw []byte) []byte { return raw[:len(raw)-1] },
		func(raw []byte) []byte { return append(raw, 0) },
	} {
		if _, err := DecodePhysicalPeerDown(t.Context(), mutate(peerDownFrameForTest(4, nil, false)), budget); err == nil {
			t.Fatal("malformed or nonphysical source was treated as neighbor session evidence")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := DecodePhysicalPeerDown(ctx, peerDownFrameForTest(4, nil, false), budget); err == nil {
		t.Fatal("canceled source returned physical evidence")
	}
	if _, err := DecodePhysicalPeerDown(t.Context(), peerDownFrameForTest(4, nil, false), PeerMessageBudget{1, 1}); err == nil {
		t.Fatal("source admission returned a partial frame")
	}
}
