// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestBGPAS4ReconstructionKeepsLegacyPrefixSetsAndConfederations(t *testing.T) {
	cases := []struct {
		name                string
		old, extended, want []ASPathSegment
		discarded           bool
	}{
		{"old-speaker prepend", []ASPathSegment{{ASPathSequence, []uint32{65001, 23456, 23456}}}, []ASPathSegment{{ASPathSequence, []uint32{4200000001, 4200000002}}}, []ASPathSegment{{ASPathSequence, []uint32{65001}}, {ASPathSequence, []uint32{4200000001, 4200000002}}}, false},
		{"set counts once", []ASPathSegment{{ASPathSet, []uint32{65001, 65002, 65003}}, {ASPathSequence, []uint32{23456}}}, []ASPathSegment{{ASPathSequence, []uint32{4200000001}}}, []ASPathSegment{{ASPathSet, []uint32{65001, 65002, 65003}}, {ASPathSequence, []uint32{4200000001}}}, false},
		{"leading and adjoining confederations", []ASPathSegment{{ASPathConfedSequence, []uint32{65010}}, {ASPathSequence, []uint32{65001}}, {ASPathConfedSet, []uint32{65020, 65021}}, {ASPathSequence, []uint32{23456}}}, []ASPathSegment{{ASPathSequence, []uint32{4200000001}}}, []ASPathSegment{{ASPathConfedSequence, []uint32{65010}}, {ASPathSequence, []uint32{65001}}, {ASPathConfedSet, []uint32{65020, 65021}}, {ASPathSequence, []uint32{4200000001}}}, false},
		{"full replacement keeps leading confed", []ASPathSegment{{ASPathConfedSet, []uint32{65020}}, {ASPathSequence, []uint32{23456}}}, []ASPathSegment{{ASPathConfedSequence, []uint32{65030}}, {ASPathSequence, []uint32{4294967295}}}, []ASPathSegment{{ASPathConfedSet, []uint32{65020}}, {ASPathSequence, []uint32{4294967295}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := ASPathAttributes{Path: asPathSegmentWire(tc.old, 2), AS4Path: asPathSegmentWire(tc.extended, 4)}
			got, err := ReconstructASPath(t.Context(), input, ASPathParseBudget{1 << 20, 1 << 20})
			if err != nil || got.AS4Action != "reconstructed" || got.AS4ConfederationsDiscarded != tc.discarded || !reflect.DeepEqual(got.Segments, tc.want) {
				t.Fatal("AS4 reconstruction lost required legacy prefix or segment semantics", got, err)
			}
			input.Path[2] ^= 0xff
			input.AS4Path[2] ^= 0xff
			if !reflect.DeepEqual(got.Segments, tc.want) {
				t.Fatal("AS4 reconstruction retained mutable source bytes")
			}
		})
	}
}

func TestBGPAS4ReconstructionDiscardsOnlyOptionalUnusableEvidence(t *testing.T) {
	old := []ASPathSegment{{ASPathSequence, []uint32{65001}}}
	cases := []struct {
		name   string
		input  ASPathAttributes
		action string
	}{
		{"absent", ASPathAttributes{Path: asPathSegmentWire(old, 2)}, "absent"},
		{"four-byte source", ASPathAttributes{FourOctetSession: true, Path: asPathSegmentWire(old, 4), AS4Path: []byte{5}}, "ignored_four_octet_session"},
		{"legacy aggregation", ASPathAttributes{Path: asPathSegmentWire(old, 2), AS4Path: asPathSegmentWire(old, 4), AggregatorPresent: true, AS4AggregatorPresent: true, AggregatorASN: 65001}, "ignored_legacy_aggregation"},
		{"malformed optional", ASPathAttributes{Path: asPathSegmentWire(old, 2), AS4Path: []byte{2, 1, 0}}, "ignored_malformed"},
		{"optional path longer", ASPathAttributes{Path: asPathSegmentWire(old, 2), AS4Path: asPathSegmentWire([]ASPathSegment{{ASPathSequence, []uint32{4200000001, 4200000002}}}, 4)}, "ignored_longer_than_legacy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReconstructASPath(t.Context(), tc.input, ASPathParseBudget{1 << 20, 1 << 20})
			if err != nil || got.AS4Action != tc.action || !reflect.DeepEqual(got.Segments, old) {
				t.Fatal("AS4 discard changed valid original path or provenance", got, err)
			}
		})
	}
	input := ASPathAttributes{Path: asPathSegmentWire([]ASPathSegment{{ASPathSequence, []uint32{23456}}}, 2), AS4Path: asPathSegmentWire([]ASPathSegment{{ASPathSequence, []uint32{4200000001}}}, 4)}
	for _, budget := range []ASPathParseBudget{{0, 100}, {100, 0}, {40, 100}, {1000, 8}, {1000, 20}} {
		got, err := ReconstructASPath(t.Context(), input, budget)
		if !errors.Is(err, ErrASPathBudget) || !reflect.DeepEqual(got, ASPathReconstruction{}) {
			t.Fatal("AS4 partial output escaped aggregate operation admission", budget, got, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := ReconstructASPath(ctx, input, ASPathParseBudget{1 << 20, 1 << 20}); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, ASPathReconstruction{}) {
		t.Fatal("canceled AS4 reconstruction retained output", got, err)
	}

	if got, err := ReconstructASPath(t.Context(), ASPathAttributes{}, ASPathParseBudget{1 << 20, 1 << 20}); !errors.Is(err, ErrASPathSyntax) || !reflect.DeepEqual(got, ASPathReconstruction{}) {
		t.Fatal("absent mandatory AS_PATH became a complete empty path", got, err)
	}
	empty, err := ReconstructASPath(t.Context(), ASPathAttributes{Path: []byte{}}, ASPathParseBudget{1, 1})
	if err != nil || empty.Segments == nil || len(empty.Segments) != 0 || empty.AS4Action != "absent" {
		t.Fatal("present empty mandatory AS_PATH was refused", empty, err)
	}
	input.Path = []byte{2, 1, 0}
	if got, err := ReconstructASPath(t.Context(), input, ASPathParseBudget{1 << 20, 1 << 20}); !errors.Is(err, ErrASPathSyntax) || !reflect.DeepEqual(got, ASPathReconstruction{}) {
		t.Fatal("malformed mandatory AS_PATH was hidden by optional AS4 data", got, err)
	}
}
