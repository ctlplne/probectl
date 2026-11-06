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

func TestBGPUpdateFrameKeepsWithdrawalsAttributesAndExactCompletion(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		withdrawn, attr, nlri []byte
		family                RouteFamily
		end                   bool
		attributes            []RouteAttribute
	}{
		{"legacy-end", nil, nil, nil, RouteFamily{1, 1}, true, []RouteAttribute{}},
		{"multiprotocol-end", nil, []byte{0x80, 15, 3, 0, 2, 1}, nil, RouteFamily{2, 1}, true, []RouteAttribute{{0x80, 15, []byte{0, 2, 1}}}},
		{"withdrawal-and-announcement", []byte{24, 192, 0, 2}, []byte{0x40, 1, 1, 0, 0x40, 2, 0}, []byte{0}, RouteFamily{}, false, []RouteAttribute{{0x40, 1, []byte{0}}, {0x40, 2, []byte{}}}},
		{"default-is-not-end", nil, nil, []byte{0}, RouteFamily{}, false, []RouteAttribute{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := endOfRIBFrameForTest(tc.withdrawn, tc.attr, tc.nlri)
			out, err := ParseBGPUpdateFrame(context.Background(), raw, UpdateFrameBudget{128 * int64(len(raw)), 8 * int64(len(raw))})
			if err != nil || !bytes.Equal(out.WithdrawnIPv4, tc.withdrawn) || !bytes.Equal(out.ReachableIPv4, tc.nlri) || out.EndOfRIB != tc.family || out.HasEndOfRIB != tc.end {
				t.Fatal("complete UPDATE lost withdrawal, announcement or exact completion", err)
			}
			if !reflect.DeepEqual(out.Attributes, tc.attributes) {
				t.Fatal("complete UPDATE changed its full attribute block", err)
			}
			clear(raw)
			if !bytes.Equal(out.WithdrawnIPv4, tc.withdrawn) || !bytes.Equal(out.ReachableIPv4, tc.nlri) || !reflect.DeepEqual(out.Attributes, tc.attributes) {
				t.Fatal("input mutation changed owned UPDATE regions")
			}
		})
	}
}

func TestBGPUpdateFrameRefusesMalformedTailAdmissionAndCancellation(t *testing.T) {
	good := endOfRIBFrameForTest([]byte{0}, []byte{0x40, 1, 1, 0, 0x40, 2, 0}, []byte{0})
	budget := UpdateFrameBudget{1 << 20, 1 << 20}
	variants := [][]byte{nil, append([]byte(nil), good[:18]...), endOfRIBFrameForTest(nil, []byte{0x40, 1, 1, 0, 0x50, 2, 0}, nil)}
	for _, mutate := range []func([]byte){
		func(raw []byte) { raw[0] = 0 },
		func(raw []byte) { raw[18] = 1 },
		func(raw []byte) { binary.BigEndian.PutUint16(raw[16:18], uint16(len(raw)-1)) },
		func(raw []byte) { binary.BigEndian.PutUint16(raw[19:21], 65535) },
		func(raw []byte) { binary.BigEndian.PutUint16(raw[22:24], 65535) },
	} {
		raw := append([]byte(nil), good...)
		mutate(raw)
		variants = append(variants, raw)
	}
	for _, raw := range variants {
		out, err := ParseBGPUpdateFrame(context.Background(), raw, budget)
		if !errors.Is(err, ErrBGPUpdateFrame) || !reflect.DeepEqual(out, UpdateFrame{}) {
			t.Fatal("malformed UPDATE exposed a partial withdrawal or route", err)
		}
	}
	for _, limited := range []UpdateFrameBudget{{0, 10000}, {10000, 0}, {128*int64(len(good)) - 1, 8 * int64(len(good))}, {128 * int64(len(good)), 8*int64(len(good)) - 1}} {
		out, err := ParseBGPUpdateFrame(context.Background(), good, limited)
		if !errors.Is(err, ErrBGPUpdateFrameBudget) || !reflect.DeepEqual(out, UpdateFrame{}) {
			t.Fatal("unadmitted UPDATE exposed partial regions", err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{canceled, &peerUpCancelContext{Context: context.Background()}} {
		out, err := ParseBGPUpdateFrame(ctx, good, budget)
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(out, UpdateFrame{}) {
			t.Fatal("canceled UPDATE retained a partial route change", err)
		}
	}
}
