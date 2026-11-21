// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestIRRRPSLIndexesExactRouteAndOrigin(t *testing.T) {
	const content = `% A local fixture authored for this test.

route: 192.0.2.0/24
origin: AS64498 # A separate origin for the same prefix.
descr: omitted details
+ more omitted details
last-modified: 2026-11-17T09:30:00Z
source: LAB

route: 192.0.2.0/24
origin: as64497
source: lab

route6: 2001:db8:4000::/48
origin: AS4294967295
source: LAB

person: Irrelevant Example
address: ignored
source: LAB
`
	generated := time.Date(2026, time.November, 19, 0, 0, 0, 0, time.UTC)
	index, err := parseIRRRPSL(t.Context(), strings.NewReader(content), "LAB", generated, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	v4, v6 := index[netip.MustParsePrefix("192.0.2.0/24")], index[netip.MustParsePrefix("2001:db8:4000::/48")]
	if len(index) != 2 || len(v4) != 2 || len(v6) != 1 || v4[0].Origin != 64497 || v4[1].Origin != 64498 ||
		!v4[0].ModifiedAt.IsZero() || v4[1].ModifiedAt.Format(time.RFC3339) != "2026-11-17T09:30:00Z" || v6[0].Origin != 4294967295 {
		t.Fatalf("the index changed exact addresses, sources, origins or clocks: %+v", index)
	}
}

func TestIRRRPSLLeavesIncompleteSnapshotUnavailable(t *testing.T) {
	const record = "route: 192.0.2.0/24\norigin: AS64497\nsource: LAB\n"
	generated := time.Date(2026, time.November, 19, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, content string
		work          int64
		want          error
	}{
		{"record missing origin", record + "\nroute6: 2001:db8::/32\nsource: LAB\n", 1 << 20, errIRRInput},
		{"foreign source", record + "\nroute6: 2001:db8::/32\norigin: AS64497\nsource: OTHER\n", 1 << 20, errIRRInput},
		{"duplicate route identity", record + "\n" + record, 1 << 20, errIRRInput},
		{"invalid uint32", strings.Replace(record, "64497", "4294967296", 1), 1 << 20, errIRRInput},
		{"future clock", record + "last-modified: 2026-11-20T00:00:00Z\n", 1 << 20, errIRRInput},
		{"work budget", record, 5, errIRRBudget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			index, err := parseIRRRPSL(t.Context(), strings.NewReader(tc.content), "LAB", generated, 1<<20, tc.work)
			if index != nil || !errors.Is(err, tc.want) {
				t.Fatalf("expected the entire snapshot to be refused with %v, got %v and %v", tc.want, index, err)
			}
		})
	}
}
