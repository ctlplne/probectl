// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"testing"
	"time"
)

// U-047 cold-start contract: a freshly-constructed store (a control-plane
// restart) holds NO state — an empty, non-panicking snapshot per tenant —
// and rebuilds the graph as observations replay from the stream.
func TestMemoryStoreColdStartRebuilds(t *testing.T) {
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	// Cold start: empty, queryable, no stale data, no cross-tenant bleed.
	fresh := NewMemoryStore()
	for _, tenant := range []string{"t-a", "t-b", "never-seen"} {
		if snap := fresh.Latest(tenant); len(snap.Nodes) != 0 || len(snap.Edges) != 0 {
			t.Fatalf("cold start for %s is not empty: %+v", tenant, snap)
		}
	}

	// Rebuild: the same observations the consumer replays from the bus refill
	// the graph (this is the rebuild-on-restart path, ADR docs/adr/volatile-stores.md).
	fresh.ObserveServiceEdge("t-a", ServiceEdgeInput{Source: "api", Destination: "db", DestPort: 5432, Transport: "tcp"}, at)
	snap := fresh.Latest("t-a")
	if len(snap.Nodes) == 0 || len(snap.Edges) == 0 {
		t.Fatalf("graph did not rebuild from observations: %+v", snap)
	}
	// Other tenants remain empty — a cold start surfaces nothing it has not
	// yet re-derived for that tenant.
	if snap := fresh.Latest("t-b"); len(snap.Edges) != 0 {
		t.Fatalf("t-b leaked state: %+v", snap)
	}
}
