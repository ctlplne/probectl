// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"
	"testing"
)

func TestRoutingMessageDispatchKeepsCompleteFamiliesAndNoInventedCompletion(t *testing.T) {
	header := make([]byte, bmpPeerHeaderLen)
	header[0] = 3
	for _, tc := range []struct {
		withdrawn, attributes, nlri []byte
		mask                        uint8
	}{
		{nil, nil, nil, 1},
		{nil, []byte{128, 15, 3, 0, 2, 1}, nil, 2},
		{[]byte{0}, nil, nil, 1},
		{nil, []byte{128, 14, 4, 0, 2, 1, 0}, []byte{0}, 3},
		{nil, []byte{64, 1, 1, 0}, nil, 0},
	} {
		raw := sourceRouteFrameForTest(header, endOfRIBFrameForTest(tc.withdrawn, tc.attributes, tc.nlri))
		budget := UpdateFrameBudget{128 * int64(len(raw)), 8 * int64(len(raw))}
		got, err := parseRoutingMessageFamilyMask(t.Context(), raw, budget)
		if err != nil || got != tc.mask {
			t.Fatal("complete source message lost family dispatch or invented completion", got, tc.mask, err)
		}
		short := append([]byte(nil), raw[:len(raw)-1]...)
		binary.BigEndian.PutUint32(short[1:5], uint32(len(short)))
		if mask, err := parseRoutingMessageFamilyMask(t.Context(), short, budget); err == nil || mask != 0 {
			t.Fatal("malformed source message exposed a partial family dispatch", mask, err)
		}
		if mask, err := parseRoutingMessageFamilyMask(t.Context(), raw, UpdateFrameBudget{1, 1}); err == nil || mask != 0 {
			t.Fatal("unadmitted message exposed family dispatch", mask, err)
		}
	}
	for _, attr := range [][]byte{{128, 14, 2, 0, 2}, {128, 15, 3, 0, 99, 1}, {128, 15, 3, 0, 2, 128}} {
		raw := sourceRouteFrameForTest(header, endOfRIBFrameForTest(nil, attr, nil))
		if mask, err := parseRoutingMessageFamilyMask(t.Context(), raw, UpdateFrameBudget{1 << 20, 1 << 20}); err == nil || mask != 0 {
			t.Fatal("unsupported family exposed partial dispatch", mask, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if mask, err := parseRoutingMessageFamilyMask(ctx, nil, UpdateFrameBudget{1 << 20, 1 << 20}); err == nil || mask != 0 {
		t.Fatal("canceled dispatch retained work", mask, err)
	}
}
