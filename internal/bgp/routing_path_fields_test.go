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
	"strings"
	"testing"
)

func TestRoutingPathFieldsKeepCompleteSemanticsAndExplicitUnknowns(t *testing.T) {
	for _, tc := range []struct {
		name            string
		path            []ASPathSegment
		text            string
		origin, transit uint32
	}{
		{"prepends", []ASPathSegment{{ASPathSequence, []uint32{65010, 65010, 64500}}}, "65010 65010 64500", 64500, 65010},
		{"direct", []ASPathSegment{{ASPathSequence, []uint32{64500, 64500}}}, "64500 64500", 64500, 0},
		{"origin-set", []ASPathSegment{{ASPathSequence, []uint32{65010}}, {ASPathSet, []uint32{64500, 64501}}}, "65010 {64500,64501}", 0, 0},
		{"first-set", []ASPathSegment{{ASPathSet, []uint32{65010, 65011}}, {ASPathSequence, []uint32{64500}}}, "{65010,65011} 64500", 64500, 0},
		{"confederations", []ASPathSegment{{ASPathConfedSequence, []uint32{65001, 65001}}, {ASPathConfedSet, []uint32{65003, 65002}}, {ASPathSequence, []uint32{4294967295, 4000000000}}}, "(65001 65001) [65003,65002] 4294967295 4000000000", 4000000000, 4294967295},
		{"as-trans", []ASPathSegment{{ASPathSequence, []uint32{65010, 23456}}}, "65010 23456", 0, 0},
		{"zero-origin", []ASPathSegment{{ASPathSequence, []uint32{65010, 0}}}, "65010 0", 0, 0},
		{"empty", nil, "", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ProjectRoutingPathFields(t.Context(), tc.path, ASPathParseBudget{MemoryBytes: 8 << 20, WorkUnits: 8 << 20})
			if err != nil || got.ASPathText != tc.text || len(got.ASPath) != len(tc.path) || (tc.origin == 0) != (got.OriginAS == nil) || (tc.transit == 0) != (got.FirstTransitAS == nil) {
				t.Fatal("routing field projection lost complete semantics or explicit unknowns", got, err)
			}
			if (got.OriginAS != nil && *got.OriginAS != tc.origin) || (got.FirstTransitAS != nil && *got.FirstTransitAS != tc.transit) {
				t.Fatal("routing field projection guessed path endpoints", got)
			}
			for i, segment := range tc.path {
				if !reflect.DeepEqual(got.ASPath[i], segment) {
					t.Fatal("routing field projection flattened, reordered or removed path data")
				}
				got.ASPath[i].Values[0] ^= 1
				if got.ASPath[i].Values[0] == tc.path[i].Values[0] {
					t.Fatal("routing field projection shares mutable source values")
				}
			}
		})
	}
	values := make([]uint32, 65537)
	for i := range values {
		values[i] = 4294967295
	}
	got, err := ProjectRoutingPathFields(t.Context(), []ASPathSegment{{ASPathSequence, values}}, ASPathParseBudget{MemoryBytes: 8 << 20, WorkUnits: 8 << 20})
	if err != nil || len(got.ASPath[0].Values) != len(values) || strings.Count(got.ASPathText, "4294967295") != len(values) {
		t.Fatal("admitted complete reconstructed path was truncated by a former count", err)
	}
}

func TestRoutingPathFieldsRefuseWholeAdmissionMalformedAndCancelledInput(t *testing.T) {
	path := []ASPathSegment{{ASPathSequence, []uint32{65010, 64500}}}
	for _, budget := range []ASPathParseBudget{{}, {MemoryBytes: 1, WorkUnits: 8 << 20}, {MemoryBytes: 8 << 20, WorkUnits: 1}} {
		if got, err := ProjectRoutingPathFields(t.Context(), path, budget); !errors.Is(err, ErrASPathBudget) || got.ASPath != nil || got.ASPathText != "" || got.OriginAS != nil {
			t.Fatal("unadmitted routing projection returned partial fields", err)
		}
	}
	for _, malformed := range [][]ASPathSegment{{{Kind: 0, Values: []uint32{1}}}, {{Kind: ASPathSequence}}} {
		if got, err := ProjectRoutingPathFields(t.Context(), malformed, ASPathParseBudget{MemoryBytes: 8 << 20, WorkUnits: 8 << 20}); !errors.Is(err, ErrASPathSyntax) || got.ASPath != nil {
			t.Fatal("malformed routing path retained partial fields", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := ProjectRoutingPathFields(ctx, path, ASPathParseBudget{MemoryBytes: 8 << 20, WorkUnits: 8 << 20}); !errors.Is(err, context.Canceled) || got.ASPath != nil {
		t.Fatal("canceled routing projection retained partial fields", err)
	}
}
