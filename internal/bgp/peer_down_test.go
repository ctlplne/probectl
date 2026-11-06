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
	"errors"
	"reflect"
	"testing"
)

func peerDownFrameForTest(reason byte, data []byte, locRIB bool) []byte {
	up := peerUpFrameForTest(nil, nil, nil)
	raw := append([]byte(nil), up[:bmpCommonHeaderLen+bmpPeerHeaderLen]...)
	raw[5] = 2
	if locRIB {
		raw[6], raw[7] = 3, 0x80
		clear(raw[16:32])
	}
	raw = append(raw, reason)
	raw = append(raw, data...)
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	return raw
}

func peerDownNotificationForTest() []byte {
	raw := make([]byte, bgpHeaderLen)
	for i := range 16 {
		raw[i] = 255
	}
	raw[18] = 3
	raw = append(raw, 6, 2, 0, 255, 1)
	binary.BigEndian.PutUint16(raw[16:18], uint16(len(raw)))
	return raw
}

func TestBMPPeerDownKeepsNotificationFSMAndMonitoringWithdrawal(t *testing.T) {
	notification := peerDownNotificationForTest()
	for _, tc := range []struct {
		name   string
		reason byte
		data   []byte
		fsm    uint16
	}{
		{"local-notification", 1, notification, 0},
		{"remote-notification", 3, notification, 0},
		{"unknown-fsm", 2, []byte{0, 0}, 0},
		{"full-fsm", 2, []byte{255, 255}, 65535},
		{"remote-transport", 4, nil, 0},
		{"monitoring-withdrawal", 5, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := peerDownFrameForTest(tc.reason, tc.data, false)
			out, err := ParseBMPPeerDown(context.Background(), raw, PeerMessageBudget{128 * int64(len(raw)), 4 * int64(len(raw))})
			if err != nil || out.Reason != tc.reason || out.Header.View != BMPAdjRIBInPrePolicy || out.FSMEvent != tc.fsm || out.FSMEventKnown != (tc.fsm != 0) {
				t.Fatal("Peer Down changed notification, FSM availability or monitoring-withdrawal reason", out.Reason, out.FSMEvent, err)
			}
			if tc.reason == 1 || tc.reason == 3 {
				clear(raw)
				if !bytes.Equal(out.Notification, notification) {
					t.Fatal("Peer Down notification lost bytes or defensive ownership")
				}
			}
		})
	}
	info := []PeerDownInformation{{3, []byte("vrf-東京")}, {3, []byte("edge")}, {60000, []byte{0, 255, 1}}}
	var data []byte
	for _, value := range info {
		data = binary.BigEndian.AppendUint16(data, value.Type)
		data = binary.BigEndian.AppendUint16(data, uint16(len(value.Value)))
		data = append(data, value.Value...)
	}
	raw := peerDownFrameForTest(6, data, true)
	out, err := ParseBMPPeerDown(context.Background(), raw, PeerMessageBudget{128 * int64(len(raw)), 4 * int64(len(raw))})
	if err != nil || out.Header.View != BMPLocRIB || out.Reason != 6 || !out.Header.Filtered || !reflect.DeepEqual(out.Information, info) {
		t.Fatal("Loc-RIB Peer Down lost ordered names or selected-view withdrawal", err)
	}
	clear(raw)
	if !reflect.DeepEqual(out.Information, info) {
		t.Fatal("Loc-RIB withdrawal metadata shared mutable source bytes")
	}
}

func TestBMPPeerDownRefusesMalformedAndWrongViewLifecycle(t *testing.T) {
	budget := PeerMessageBudget{1 << 20, 1 << 20}
	t.Run("loc-rib-reason", func(t *testing.T) {
		out, err := ParseBMPPeerDown(context.Background(), peerDownFrameForTest(4, nil, true), budget)
		if !errors.Is(err, ErrBMPPeerDown) || !reflect.DeepEqual(out, PeerDown{}) {
			t.Fatal("Loc-RIB lifecycle accepted an adjacent-view closure reason", err)
		}
	})
	for _, tc := range []struct {
		reason byte
		data   []byte
	}{
		{0, nil}, {7, nil}, {255, nil}, {1, nil}, {3, []byte{0}},
		{2, nil}, {2, []byte{0}}, {2, []byte{0, 0, 0}}, {4, []byte{0}}, {5, []byte{0}},
		{6, []byte{0}}, {6, []byte{0, 3, 0, 2, 1}}, {6, []byte{0, 3, 0, 1, 1, 0}},
	} {
		out, err := ParseBMPPeerDown(context.Background(), peerDownFrameForTest(tc.reason, tc.data, false), budget)
		if !errors.Is(err, ErrBMPPeerDown) || !reflect.DeepEqual(out, PeerDown{}) {
			t.Fatal("malformed Peer Down returned partial lifecycle metadata", tc.reason, err)
		}
	}
	good := peerDownFrameForTest(1, peerDownNotificationForTest(), false)
	for _, mutate := range []func([]byte){
		func(raw []byte) { raw[0] = 2 },
		func(raw []byte) { raw[5] = 3 },
		func(raw []byte) { raw[1]++ },
		func(raw []byte) { raw[49] = 0 },
		func(raw []byte) { raw[49+18] = 2 },
		func(raw []byte) { raw[49+17]++ },
	} {
		raw := append([]byte(nil), good...)
		mutate(raw)
		out, err := ParseBMPPeerDown(context.Background(), raw, budget)
		if !errors.Is(err, ErrBMPPeerDown) || !reflect.DeepEqual(out, PeerDown{}) {
			t.Fatal("broken frame or notification authorized lifecycle metadata", err)
		}
	}
	for _, limited := range []PeerMessageBudget{{0, 10000}, {10000, 0}, {128*int64(len(good)) - 1, 4 * int64(len(good))}, {128 * int64(len(good)), 4*int64(len(good)) - 1}} {
		out, err := ParseBMPPeerDown(context.Background(), good, limited)
		if !errors.Is(err, ErrBMPPeerDownBudget) || !reflect.DeepEqual(out, PeerDown{}) {
			t.Fatal("unadmitted Peer Down returned lifecycle metadata", err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{canceled, &peerUpCancelContext{Context: context.Background()}} {
		raw := peerDownFrameForTest(6, []byte{0, 3, 0, 1, 1, 0, 3, 0, 1, 2, 0, 3, 0, 1, 3}, true)
		out, err := ParseBMPPeerDown(ctx, raw, budget)
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(out, PeerDown{}) {
			t.Fatal("canceled Peer Down retained partial lifecycle metadata", err)
		}
	}
}
