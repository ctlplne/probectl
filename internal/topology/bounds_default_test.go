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

// TestDefaultTopologyBoundsNonZero pins the AI-08 acceptance that a default
// deployment reports non-zero node/edge caps and a non-zero staleness horizon,
// through every constructor path that a default deployment uses.
func TestDefaultTopologyBoundsNonZero(t *testing.T) {
	def := DefaultBounds()
	if def.MaxNodes <= 0 || def.MaxEdges <= 0 || def.Staleness <= 0 {
		t.Fatalf("DefaultBounds must be non-zero on every field: %+v", def)
	}

	// The caps must sit above the largest supported single-tenant graph (the
	// S43 XL fabric: ~31k nodes / ~46k edges) so the default bounds churn, not
	// a legitimate topology.
	if def.MaxNodes < 50_000 || def.MaxEdges < 50_000 {
		t.Fatalf("default caps too small to hold a supported XL graph: %+v", def)
	}

	for _, tc := range []struct {
		name  string
		graph *Graph
	}{
		{name: "NewGraph", graph: NewGraph("tenant-a")},
		{name: "MemoryStore graph", graph: NewMemoryStore().graph("tenant-a")},
		{name: "IndexedStore inner graph", graph: NewIndexedStore().graph("tenant-a").inner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.graph.Bounds()
			if got != def {
				t.Fatalf("default graph bounds = %+v, want DefaultBounds %+v", got, def)
			}
		})
	}
}

// TestLatestHorizonUsesConfiguredDefault proves the aged-out window matches the
// configured default horizon exactly, referencing the shipped constant.
func TestLatestHorizonUsesConfiguredDefault(t *testing.T) {
	store := NewMemoryStore()
	tenant, err := store.ForTenant("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0)
	// Live leading edge two horizons after the stale element.
	live := base.Add(2 * DefaultStalenessHorizon)
	tenant.ObserveServiceEdge(ServiceEdgeInput{Source: "stale-svc", Destination: "stale-db", DestPort: 5432}, base)
	tenant.ObserveServiceEdge(ServiceEdgeInput{Source: "live-svc", Destination: "live-db", DestPort: 5432}, live)

	if latest := tenant.Latest(); snapshotHasID(latest, "service:stale-svc") {
		t.Fatalf("element %v past the %v horizon stayed in Latest(): %+v", 2*DefaultStalenessHorizon, DefaultStalenessHorizon, latest.Nodes)
	}

	// An element re-observed within the horizon of the leading edge stays live.
	withinHorizon := live.Add(-DefaultStalenessHorizon / 2)
	tenant.ObserveServiceEdge(ServiceEdgeInput{Source: "stale-svc", Destination: "stale-db", DestPort: 5432}, withinHorizon)
	if latest := tenant.Latest(); !snapshotHasID(latest, "service:stale-svc") {
		t.Fatalf("element re-observed within the horizon was dropped from Latest(): %+v", latest.Nodes)
	}
}
