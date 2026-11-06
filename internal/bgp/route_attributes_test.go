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

func TestBGPRouteAttributesKeepCompleteUnknownEmptyAndOwnedValues(t *testing.T) {
	path := bytes.Repeat([]byte{2, 1, 255, 255, 255, 255}, 3000)
	raw := []byte{0x40, 1, 1, 0, 0x50, 2}
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(path)))
	raw = append(raw, path...)
	raw = append(raw, 0xc0, 255, 3, 0, 255, 1, 0x40, 2, 0)
	want := []RouteAttribute{{0x40, 1, []byte{0}}, {0x50, 2, path}, {0xc0, 255, []byte{0, 255, 1}}, {0x40, 2, []byte{}}}
	out, err := ParseBGPRouteAttributes(context.Background(), raw, RouteAttributeBudget{64 * int64(len(raw)), 2 * int64(len(raw))})
	if err != nil || !reflect.DeepEqual(out, want) {
		t.Fatal("complete attributes lost order, flags, unknown or present empty path", err)
	}
	clear(raw)
	if !reflect.DeepEqual(out, want) {
		t.Fatal("input mutation changed owned route attributes")
	}
	if out[3].Value == nil {
		t.Fatal("present empty AS_PATH became a missing mandatory attribute")
	}
	out[1].Value[0] = 0
	if path[0] != 2 || out[2].Value[0] != 0 || out[2].Value[1] != 255 {
		t.Fatal("route attributes retained shared mutable values")
	}
	empty, err := ParseBGPRouteAttributes(context.Background(), nil, RouteAttributeBudget{1, 1})
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatal("complete empty attribute block became an unavailable parse", err)
	}
}

func TestBGPRouteAttributesRefuseMalformedTailAdmissionAndCancellation(t *testing.T) {
	budget := RouteAttributeBudget{1 << 20, 1 << 20}
	for _, raw := range [][]byte{
		{0}, {0x40, 2}, {0x50, 2, 0}, {0x40, 2, 1}, {0x50, 2, 0, 1},
		{0x40, 1, 1, 0, 0x40, 2, 2, 1}, {0x40, 1, 1, 0, 0x50, 2, 255, 255, 1},
	} {
		out, err := ParseBGPRouteAttributes(context.Background(), raw, budget)
		if !errors.Is(err, ErrRouteAttributes) || out != nil {
			t.Fatal("malformed attribute tail returned a partial path", err)
		}
	}
	good := []byte{0x40, 1, 1, 0, 0x40, 2, 0}
	for _, limited := range []RouteAttributeBudget{{0, 1000}, {1000, 0}, {64*int64(len(good)) - 1, 2 * int64(len(good))}, {64 * int64(len(good)), 2*int64(len(good)) - 1}} {
		out, err := ParseBGPRouteAttributes(context.Background(), good, limited)
		if !errors.Is(err, ErrRouteAttributeBudget) || out != nil {
			t.Fatal("unadmitted attributes returned partial output", err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{canceled, &peerUpCancelContext{Context: context.Background()}} {
		out, err := ParseBGPRouteAttributes(ctx, good, budget)
		if !errors.Is(err, context.Canceled) || out != nil {
			t.Fatal("canceled attributes retained a partial path", err)
		}
	}
}
