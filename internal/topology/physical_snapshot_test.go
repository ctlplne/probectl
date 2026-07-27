// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package topology

import (
	"testing"
	"time"
)

func TestPhysicalSnapshotReplaceIsSourceAndTenantScoped(t *testing.T) {
	for _, tc := range []struct {
		name  string
		store Store
	}{
		{name: "memory", store: NewMemoryStore()},
		{name: "indexed", store: NewIndexedStore()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenantA, err := tc.store.ForTenant("tenant-a")
			if err != nil {
				t.Fatal(err)
			}
			tenantB, err := tc.store.ForTenant("tenant-b")
			if err != nil {
				t.Fatal(err)
			}
			t1 := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
			t2, t3, t4 := t1.Add(time.Minute), t1.Add(2*time.Minute), t1.Add(3*time.Minute)
			edge := func(agent, remote, port string) PhysicalAdjacencyInput {
				return PhysicalAdjacencyInput{
					LocalName: "core-1", LocalPort: port,
					RemoteIdentity: remote, RemoteName: remote, RemotePort: "Ethernet1",
					Protocol: "lldp", Confidence: "0.95", SourceAgent: agent,
				}
			}
			replace := func(
				graph TenantStore,
				agent, local string,
				at time.Time,
				adjacencies ...PhysicalAdjacencyInput,
			) {
				graph.ReplacePhysicalAdjacencies(PhysicalAdjacencySnapshot{
					SourceAgent: agent, LocalAddress: local, Adjacencies: adjacencies,
				}, at)
			}

			aOne := edge("agent-a", "leaf-1", "Gi0/1")
			aTwo := edge("agent-a", "leaf-2", "Gi0/2")
			bShared := edge("agent-b", "leaf-1", "Gi0/1")
			bOnly := edge("agent-b", "leaf-3", "Gi0/3")
			replace(tenantA, "agent-a", "10.0.0.1", t1, aOne, aTwo)
			replace(tenantA, "agent-b", "10.0.0.1", t1, bShared, bOnly)
			replace(tenantB, "agent-a", "10.0.0.1", t1, edge("agent-a", "secret-leaf", "Gi0/9"))

			replace(tenantA, "agent-a", "10.0.0.1", t2, aOne)
			current := tenantA.Latest()
			if physicalEdgeCount(current) != 2 ||
				snapshotHasEdge(current, "device:10.0.0.1", "device:lldp:leaf-2") {
				t.Fatalf("partial source replacement = %+v", current.Edges)
			}
			if coverage := SnapshotCoverage(current); coverage.PhysicalEdges != 2 {
				t.Fatalf("partial physical coverage = %+v", coverage)
			}

			replace(tenantA, "agent-a", "10.0.0.1", t3)
			current = tenantA.Latest()
			if physicalEdgeCount(current) != 2 ||
				!snapshotHasEdge(current, "device:10.0.0.1", "device:lldp:leaf-1") ||
				!snapshotHasEdge(current, "device:10.0.0.1", "device:lldp:leaf-3") {
				t.Fatalf("empty agent-a snapshot touched agent-b ownership: %+v", current.Edges)
			}
			if foreign := tenantB.Latest(); physicalEdgeCount(foreign) != 1 ||
				!snapshotHasEdge(foreign, "device:10.0.0.1", "device:lldp:secret-leaf") {
				t.Fatalf("tenant-a replacement touched tenant-b: %+v", foreign.Edges)
			}

			replace(tenantA, "agent-b", "10.0.0.1", t4)
			if current = tenantA.Latest(); physicalEdgeCount(current) != 0 {
				t.Fatalf("last source empty snapshot left current physical edges: %+v", current.Edges)
			}
			if historical := tenantA.SnapshotAt(t1); physicalEdgeCount(historical) != 3 {
				t.Fatalf("source replacement destroyed historical evidence: %+v", historical.Edges)
			}
		})
	}
}

func physicalEdgeCount(snapshot Snapshot) int {
	count := 0
	for _, edge := range snapshot.Edges {
		if edge.Kind == EdgePhysical {
			count++
		}
	}
	return count
}

func snapshotHasEdge(snapshot Snapshot, from, to string) bool {
	for _, edge := range snapshot.Edges {
		if edge.Kind == EdgePhysical && edge.From == from && edge.To == to {
			return true
		}
	}
	return false
}
