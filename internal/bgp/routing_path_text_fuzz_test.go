// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import "testing"

// Canonical accepted text must round-trip without losing ASN values or segment
// syntax; every refusal is all-or-nothing under the supplied finite budget.
func FuzzRoutingPathText(f *testing.F) {
	for _, seed := range []string{"", "0", "64500 4294967295", "{1,2} (3 4) [5,6] 7 7", "4111 1111 1111 1111", "1 {2,}", "4294967296", "1\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		path, err := ParseRoutingPathText(t.Context(), text, ASPathParseBudget{MemoryBytes: 4 << 20, WorkUnits: 4 << 20})
		if err != nil {
			if path != nil {
				t.Fatal("rejected path text returned a partial path")
			}
			return
		}
		projected, err := ProjectRoutingPathFields(t.Context(), path, ASPathParseBudget{MemoryBytes: 32 << 20, WorkUnits: 32 << 20})
		if err != nil || projected.ASPathText != text {
			t.Fatal("accepted path text changed canonical values or segment syntax", err)
		}
	})
}
