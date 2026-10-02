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

// TestLatestAgesOutDecommissionedElementByDefault is the AI-08 regression: a
// default deployment (no explicit bounds) must age decommissioned elements out
// of the live view while preserving history.
//
// It drives the behavior through the real tenant-bound store entry point
// (ObserveServiceEdge / Latest / SnapshotAt) so it compiles against a baseline
// with no default horizon and FAILS there on behavior: without a default
// staleness horizon, Latest() keeps every element ever seen, so the
// decommissioned element is still present.
func TestLatestAgesOutDecommissionedElementByDefault(t *testing.T) {
	// Observe a decommissioned element, then advance the graph's live leading
	// edge far past it by observing a still-live element. The 30-day spread is
	// well beyond any sane default horizon, so the proof is robust to tuning
	// the shipped default while still pinning "a stale element ages out".
	t0 := time.Unix(1_700_000_000, 0)
	tLive := t0.Add(30 * 24 * time.Hour)

	for _, tc := range []struct {
		name  string
		store Store
	}{
		{name: "memory", store: NewMemoryStore()},
		{name: "indexed", store: NewIndexedStore()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenant, err := tc.store.ForTenant("tenant-a")
			if err != nil {
				t.Fatal(err)
			}
			tenant.ObserveServiceEdge(ServiceEdgeInput{Source: "gone-svc", Destination: "gone-db", DestPort: 5432, Transport: "tcp"}, t0)
			tenant.ObserveServiceEdge(ServiceEdgeInput{Source: "live-svc", Destination: "live-db", DestPort: 5432, Transport: "tcp"}, tLive)

			latest := tenant.Latest()
			if snapshotHasID(latest, "service:gone-svc") || snapshotHasID(latest, "service:gone-db") {
				t.Fatalf("decommissioned element persists in Latest() with no default staleness horizon: %+v", latest.Nodes)
			}
			if !snapshotHasID(latest, "service:live-svc") || !snapshotHasID(latest, "service:live-db") {
				t.Fatalf("live element missing from Latest(): %+v", latest.Nodes)
			}

			// History is preserved: a temporal query as of t0 still returns the
			// decommissioned element — aging is a live-view filter, not deletion.
			hist := tenant.SnapshotAt(t0)
			if !snapshotHasID(hist, "service:gone-svc") || !snapshotHasID(hist, "service:gone-db") {
				t.Fatalf("SnapshotAt(t0) must still return the decommissioned element (history lost): %+v", hist.Nodes)
			}
		})
	}
}
