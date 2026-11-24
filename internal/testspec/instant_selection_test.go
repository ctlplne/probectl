// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testspec

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestNormalizeInstantSelectionPreservesDefinedVantage(t *testing.T) {
	const first = "00000000-0000-4000-8000-000000000001"
	const second = "00000000-0000-4000-8000-00000000000a"
	tag := &InstantAgentTag{ContextID: first, TagID: second, Value: " East "}
	cases := []struct {
		name  string
		input InstantSelection
		want  InstantSelection
	}{
		{"sorted agents", InstantSelection{AgentIDs: []string{second, first}}, InstantSelection{AgentIDs: []string{first, second}}},
		{"exact site", InstantSelection{Site: "East office"}, InstantSelection{Site: "East office"}},
		{"exact tag", InstantSelection{Tag: tag}, InstantSelection{Tag: tag}},
		{"missing selection", InstantSelection{}, InstantSelection{}},
		{"multiple selectors", InstantSelection{AgentIDs: []string{first}, Site: "East office", Tag: tag}, InstantSelection{}},
		{"padded site", InstantSelection{Site: "East office "}, InstantSelection{}},
		{"duplicate agents", InstantSelection{AgentIDs: []string{first, first}}, InstantSelection{}},
		{"noncanonical agent", InstantSelection{AgentIDs: []string{strings.ToUpper(second)}}, InstantSelection{}},
		{"nil agent ID", InstantSelection{AgentIDs: []string{"00000000-0000-0000-0000-000000000000"}}, InstantSelection{}},
		{"broken tag context", InstantSelection{Tag: &InstantAgentTag{ContextID: "missing", TagID: second, Value: "East"}}, InstantSelection{}},
		{"broken tag ID", InstantSelection{Tag: &InstantAgentTag{ContextID: first, TagID: "missing", Value: "East"}}, InstantSelection{}},
		{"empty tag value", InstantSelection{Tag: &InstantAgentTag{ContextID: first, TagID: second}}, InstantSelection{}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			original := slices.Clone(tt.input.AgentIDs)
			got, err := NormalizeInstantSelection(tt.input)
			if reflect.DeepEqual(tt.want, InstantSelection{}) {
				if !errors.Is(err, ErrInstantSelection) || !reflect.DeepEqual(got, tt.want) {
					t.Fatalf("selection = %+v, %v, want an empty rejected selection", got, err)
				}
			} else if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("selection = %+v, %v, want %+v", got, err, tt.want)
			}
			if !slices.Equal(tt.input.AgentIDs, original) {
				t.Fatal("normalization mutated the requested agent order")
			}
		})
	}
}
