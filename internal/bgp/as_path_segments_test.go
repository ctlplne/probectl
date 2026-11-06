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

func asPathSegmentWire(segments []ASPathSegment, width int) []byte {
	var out []byte
	for _, segment := range segments {
		out = append(out, byte(segment.Kind), byte(len(segment.Values)))
		for _, asn := range segment.Values {
			if width == 4 {
				out = binary.BigEndian.AppendUint32(out, asn)
			} else {
				out = binary.BigEndian.AppendUint16(out, uint16(asn))
			}
		}
	}
	return out
}

func TestBGPASPathSegmentsPreserveOrderedSetsAndFullValues(t *testing.T) {
	for _, width := range []int{2, 4} {
		last := uint32(65535)
		if width == 4 {
			last = 4294967295
		}
		want := []ASPathSegment{{ASPathConfedSequence, []uint32{65000, 65000}}, {ASPathConfedSet, []uint32{65100, 65101}}, {ASPathSequence, []uint32{64496, 64496}}, {ASPathSet, []uint32{0, last, 64497}}, {ASPathSequence, []uint32{last}}}
		raw := asPathSegmentWire(want, width)
		got, err := ParseASPathSegments(t.Context(), raw, width, ASPathParseBudget{1 << 20, 1 << 20})
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("structured AS path lost segment kinds, order, duplicates or complete values", width, got, err)
		}
		raw[2] ^= 0xff
		if !reflect.DeepEqual(got, want) {
			t.Fatal("structured AS path retained mutable input")
		}
		got[0].Values = append(got[0].Values, 1)
		if !reflect.DeepEqual(got[1], want[1]) {
			t.Fatal("structured AS path append corrupted another segment")
		}
	}
	// More than the legacy notification parser's512 entries, without changing
	// that parser or weakening this new decoder's finite operation admission.
	want := make([]ASPathSegment, 80)
	for i := range want {
		values := make([]uint32, 255)
		for j := range values {
			values[j] = uint32(i*255 + j)
		}
		want[i] = ASPathSegment{ASPathSequence, values}
	}
	raw := asPathSegmentWire(want, 4)
	exact := ASPathParseBudget{MemoryBytes: int64(80*32 + 80*255*4), WorkUnits: int64(2 * len(raw))}
	got, err := ParseASPathSegments(t.Context(), raw, 4, exact)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("complete long AS path lost values under exact finite admission", err)
	}
	empty, err := ParseASPathSegments(t.Context(), nil, 4, ASPathParseBudget{1, 1})
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatal("complete empty AS path was replaced by invented data", empty, err)
	}
}

func TestBGPASPathSegmentsRejectIncompleteAndUnadmittedInput(t *testing.T) {
	valid := asPathSegmentWire([]ASPathSegment{{ASPathSequence, []uint32{64496, 64497}}}, 4)
	for _, raw := range [][]byte{{2}, {0, 1, 0, 0, 0, 1}, {5, 1, 0, 0, 0, 1}, {2, 0}, append(append([]byte(nil), valid...), 2, 1, 0)} {
		got, err := ParseASPathSegments(t.Context(), raw, 4, ASPathParseBudget{1 << 20, 1 << 20})
		if !errors.Is(err, ErrASPathSyntax) || got != nil {
			t.Fatal("malformed tail or segment returned a partial path", got, err)
		}
	}
	for _, width := range []int{-1, 0, 1, 3, 8} {
		if got, err := ParseASPathSegments(t.Context(), valid, width, ASPathParseBudget{1 << 20, 1 << 20}); !errors.Is(err, ErrASPathSyntax) || got != nil {
			t.Fatal("ASN width was guessed", width, err)
		}
	}
	for _, budget := range []ASPathParseBudget{{0, 100}, {100, 0}, {39, 100}, {100, int64(2*len(valid) - 1)}} {
		if got, err := ParseASPathSegments(t.Context(), valid, 4, budget); !errors.Is(err, ErrASPathBudget) || got != nil {
			t.Fatal("structured path escaped complete resource admission", budget, got, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := ParseASPathSegments(ctx, valid, 4, ASPathParseBudget{1 << 20, 1 << 20}); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatal("canceled structured path retained work", got, err)
	}
}
