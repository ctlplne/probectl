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

func routeASSequenceForTest(width int, values ...uint32) []byte {
	raw := []byte{2, byte(len(values))}
	for _, value := range values {
		if width == 2 {
			raw = binary.BigEndian.AppendUint16(raw, uint16(value))
		} else {
			raw = binary.BigEndian.AppendUint32(raw, value)
		}
	}
	return raw
}

func routeASAggregatorForTest(width int, value uint32) []byte {
	var raw []byte
	if width == 2 {
		raw = binary.BigEndian.AppendUint16(raw, uint16(value))
	} else {
		raw = binary.BigEndian.AppendUint32(raw, value)
	}
	return append(raw, 192, 0, 2, 1)
}

func TestRouteASPathKeepsAggregationProvenanceAndCompletePath(t *testing.T) {
	for _, name := range []string{"legacy-reconstruction", "legacy-aggregation", "as-trans-aggregation", "bad-aggregator", "bad-as4-aggregator", "four-octet-session", "malformed-optional-path", "present-empty-path"} {
		t.Run(name, func(t *testing.T) {
			attributes := []RouteAttribute{{0x50, 2, routeASSequenceForTest(2, 65000, 23456)}, {0xe0, 17, routeASSequenceForTest(4, 4200000001)}, {0xc0, 255, []byte{1, 2, 3}}}
			width := 2
			want := RouteASPath{Path: ASPathReconstruction{Segments: []ASPathSegment{{ASPathSequence, []uint32{65000}}, {ASPathSequence, []uint32{4200000001}}}, AS4Action: "reconstructed"}}
			switch name {
			case "legacy-aggregation":
				attributes = append(attributes, RouteAttribute{0xc0, 7, routeASAggregatorForTest(2, 65010)}, RouteAttribute{0xe0, 18, routeASAggregatorForTest(4, 4200000002)})
				want = RouteASPath{Path: ASPathReconstruction{Segments: []ASPathSegment{{ASPathSequence, []uint32{65000, 23456}}}, AS4Action: "ignored_legacy_aggregation"}, IgnoredAttributes: []byte{17, 18}}
			case "as-trans-aggregation":
				attributes = append(attributes, RouteAttribute{0xc0, 7, routeASAggregatorForTest(2, 23456)}, RouteAttribute{0xc0, 18, routeASAggregatorForTest(4, 4200000002)})
				want.IgnoredAttributes = []byte{7}
			case "bad-aggregator":
				attributes = append(attributes, RouteAttribute{0xc0, 7, []byte{0, 1}}, RouteAttribute{0xc0, 18, routeASAggregatorForTest(4, 4200000002)})
				want.IgnoredAttributes = []byte{7}
			case "bad-as4-aggregator":
				attributes = append(attributes, RouteAttribute{0xc0, 7, routeASAggregatorForTest(2, 65010)}, RouteAttribute{0xc0, 18, []byte{0, 1}})
				want.IgnoredAttributes = []byte{18}
			case "four-octet-session":
				width = 4
				attributes = []RouteAttribute{{0x40, 2, routeASSequenceForTest(4, 4294967295)}, {0, 17, []byte{1}}, {0, 18, []byte{0}}}
				want = RouteASPath{Path: ASPathReconstruction{Segments: []ASPathSegment{{ASPathSequence, []uint32{4294967295}}}, AS4Action: "ignored_four_octet_session"}, IgnoredAttributes: []byte{17, 18}}
			case "malformed-optional-path":
				attributes[1].Value = []byte{1}
				want = RouteASPath{Path: ASPathReconstruction{Segments: []ASPathSegment{{ASPathSequence, []uint32{65000, 23456}}}, AS4Action: "ignored_malformed"}, IgnoredAttributes: []byte{17}}
			case "present-empty-path":
				attributes = []RouteAttribute{{0x40, 2, nil}}
				want = RouteASPath{Path: ASPathReconstruction{Segments: []ASPathSegment{}, AS4Action: "absent"}}
			}
			out, err := ReconstructRouteASPath(context.Background(), attributes, width, ASPathParseBudget{1 << 20, 1 << 20})
			if err != nil || !reflect.DeepEqual(out, want) {
				t.Fatal("attribute AS4 aggregation provenance changed the reconstructed path", out, err)
			}
			for _, attribute := range attributes {
				clear(attribute.Value)
			}
			if !reflect.DeepEqual(out, want) {
				t.Fatal("input mutation changed complete reconstructed attribute semantics")
			}
		})
	}
}

func TestRouteASPathRefusesAmbiguityAdmissionAndCancellation(t *testing.T) {
	path := RouteAttribute{0x40, 2, routeASSequenceForTest(2, 65000, 23456)}
	extended := RouteAttribute{0xc0, 17, routeASSequenceForTest(4, 4200000001)}
	for _, attributes := range [][]RouteAttribute{
		nil, {extended}, {path, path}, {path, extended, extended},
		{{0x80, 2, path.Value}}, {{0x60, 2, path.Value}}, {path, {0x40, 17, extended.Value}},
		{path, {0xc0, 7, []byte{0}}, {0xc0, 7, []byte{1}}},
	} {
		out, err := ReconstructRouteASPath(context.Background(), attributes, 2, ASPathParseBudget{1 << 20, 1 << 20})
		if !errors.Is(err, ErrRouteASAttributes) || !reflect.DeepEqual(out, RouteASPath{}) {
			t.Fatal("missing, invalid or ambiguous attributes exposed a partial path", err)
		}
	}
	good := []RouteAttribute{path, extended}
	for _, width := range []int{0, 3, 8} {
		out, err := ReconstructRouteASPath(context.Background(), good, width, ASPathParseBudget{1 << 20, 1 << 20})
		if !errors.Is(err, ErrRouteASAttributes) || !reflect.DeepEqual(out, RouteASPath{}) {
			t.Fatal("unsupported source width guessed path attributes", width, err)
		}
	}
	for _, budget := range []ASPathParseBudget{{0, 10000}, {10000, 0}, {127, 10000}, {1 << 20, 1}, {129, 1 << 20}} {
		out, err := ReconstructRouteASPath(context.Background(), good, 2, budget)
		if !errors.Is(err, ErrASPathBudget) || !reflect.DeepEqual(out, RouteASPath{}) {
			t.Fatal("unadmitted attributes exposed a partial reconstruction", err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{canceled, &peerUpCancelContext{Context: context.Background()}} {
		out, err := ReconstructRouteASPath(ctx, good, 2, ASPathParseBudget{1 << 20, 1 << 20})
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(out, RouteASPath{}) {
			t.Fatal("canceled attributes retained a reconstructed path", err)
		}
	}
}
