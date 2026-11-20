// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"slices"
	"testing"
)

func TestASPathHistoryKeepsPrependsAndUncertainAdjacency(t *testing.T) {
	for _, tc := range []struct {
		name     string
		segments []ASPathSegment
		length   int64
		origins  []uint32
		upstream uint32
		unknown  bool
	}{
		{"prepends", []ASPathSegment{{ASPathConfedSequence, []uint32{65000}}, {ASPathSequence, []uint32{64496, 64497, 64497}}}, 3, []uint32{64497}, 64496, false},
		{"set origin", []ASPathSegment{{ASPathSet, []uint32{64499, 64497, 64497, 23456}}}, 1, []uint32{64497, 64499}, 0, true},
		{"set boundary", []ASPathSegment{{ASPathSet, []uint32{64499, 64496}}, {ASPathSequence, []uint32{64497, 64497}}}, 3, []uint32{64497}, 0, false},
		{"confederation boundary", []ASPathSegment{{ASPathSequence, []uint32{64496}}, {ASPathConfedSet, []uint32{65000}}, {ASPathSequence, []uint32{64497}}}, 2, []uint32{64497}, 0, false},
		{"unreconstructed origin", []ASPathSegment{{ASPathSequence, []uint32{64496, 23456}}}, 2, nil, 0, true},
		{"local empty path", nil, 0, nil, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SummarizeASPath(tc.segments)
			if got.Length != tc.length || !slices.Equal(got.PossibleOrigins, tc.origins) || got.OriginAmbiguous != tc.unknown || got.Upstream != tc.upstream {
				t.Fatalf("path claims exceeded the original ordered evidence: %+v", got)
			}
		})
	}
	originalSet := []ASPathSegment{{ASPathSet, []uint32{64497, 64496}}}
	reorderedSet := []ASPathSegment{{ASPathSet, []uint32{64496, 64497}}}
	if changes := CompareASPaths(originalSet, reorderedSet); changes != (ASPathChanges{}) || originalSet[0].Values[0] != 64497 {
		t.Fatalf("set order created a change or altered the original: %+v", changes)
	}
}

func TestASPathHistorySeparatesChangesInEvidenceAndPath(t *testing.T) {
	sequence := func(values ...uint32) []ASPathSegment {
		return []ASPathSegment{{ASPathSequence, values}}
	}
	baseline := sequence(64496, 64497)
	for _, tc := range []struct {
		name string
		path []ASPathSegment
		want ASPathChanges
	}{
		{"repeat", sequence(64496, 64497), ASPathChanges{}},
		{"upstream", sequence(64499, 64497), ASPathChanges{SegmentsChanged: true, UpstreamChanged: true}},
		{"origin", sequence(64496, 64499), ASPathChanges{SegmentsChanged: true, OriginChanged: true}},
		{"prepend", sequence(64496, 64497, 64497), ASPathChanges{SegmentsChanged: true, LengthChanged: true}},
		{"uncertain set", []ASPathSegment{{ASPathSequence, []uint32{64496}}, {ASPathSet, []uint32{64497, 64499}}},
			ASPathChanges{SegmentsChanged: true, OriginEvidenceChanged: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CompareASPaths(baseline, tc.path); got != tc.want {
				t.Fatalf("changes %+v want %+v", got, tc.want)
			}
		})
	}
}
