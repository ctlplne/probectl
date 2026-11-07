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

func TestRoutingPathTextKeepsCompleteCanonicalSegmentsAndAdmission(t *testing.T) {
	budget := ASPathParseBudget{MemoryBytes: 32 << 20, WorkUnits: 32 << 20}
	texts := []string{"", "0 {64500,4294967295} (64501 64502) [64496,64497] 64500 64500", "4111 1111 1111 1111", strings.Repeat("64500 ", 65_537) + "4294967295"}
	for _, text := range texts {
		parsed, err := ParseRoutingPathText(t.Context(), text, budget)
		if err != nil {
			t.Fatal("complete routing path text lost canonical values", err)
		}
		projected, err := ProjectRoutingPathFields(t.Context(), parsed, budget)
		if err != nil || projected.ASPathText != text {
			t.Fatal("complete routing path text lost canonical values", err)
		}
		again, err := ParseRoutingPathText(t.Context(), projected.ASPathText, budget)
		if err != nil || !reflect.DeepEqual(again, parsed) {
			t.Fatal("canonical routing path text lost segment identity", err)
		}
	}
	parsed, err := ParseRoutingPathText(t.Context(), texts[3], budget)
	if err != nil || len(parsed) != 1 || len(parsed[0].Values) != 65_538 || parsed[0].Values[65_537] != ^uint32(0) {
		t.Fatal("routing path text truncated prepends or full uint32 values", err)
	}
	for _, text := range []string{" 1", "1 ", "1  2", "{1,}", "{}", "(1,2)", "[1 2]", "{1,02}", "4294967296", "1 password=value", "1 (2 3", "1 [2,3]x"} {
		if prefix, err := ParseRoutingPathText(t.Context(), text, budget); !errors.Is(err, ErrASPathSyntax) || prefix != nil {
			t.Fatal("malformed routing path text disclosed a parsed prefix", text, err)
		}
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if prefix, err := ParseRoutingPathText(canceled, texts[3], budget); !errors.Is(err, context.Canceled) || prefix != nil {
		t.Fatal("routing path text ignored cancellation", err)
	}
	if prefix, err := ParseRoutingPathText(t.Context(), texts[3], ASPathParseBudget{MemoryBytes: 4096, WorkUnits: 4096}); !errors.Is(err, ErrASPathBudget) || prefix != nil {
		t.Fatal("routing path text returned a partial budget prefix", err)
	}
}
