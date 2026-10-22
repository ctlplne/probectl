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

// TestPhysicalSnapshotRetiresTheNeighborItOnlyEvidenced is DPR-300's
// regression: when a device stops reporting an LLDP neighbor (the uplink is
// moved to another switch), the live graph dropped the old adjacency but
// kept the old neighbor's node for the whole staleness horizon, so the
// Topology page and every what-if still showed a switch the device no longer
// reported. A neighbor node evidenced only by retired adjacencies must leave
// Latest() with them, stay in SnapshotAt at its observed times, and a node
// with other evidence (a managed device, another source's current edge)
// must stay.
func TestPhysicalSnapshotRetiresTheNeighborItOnlyEvidenced(t *testing.T) {
	for _, tc := range []struct {
		name  string
		store Store
	}{
		{name: "memory", store: NewMemoryStore()},
		{name: "indexed", store: NewIndexedStore()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			graph, err := tc.store.ForTenant("tenant-a")
			if err != nil {
				t.Fatal(err)
			}
			t1 := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
			t2 := t1.Add(15 * time.Second)
			nbr := func(agent, chassis, name string) PhysicalAdjacencyInput {
				return PhysicalAdjacencyInput{LocalName: "core-1", LocalPort: "eth0", RemoteIdentity: chassis,
					RemoteName: name, RemotePort: "Gi0/48", Protocol: "lldp", SourceAgent: agent}
			}
			replace := func(agent, local string, at time.Time, adjacencies ...PhysicalAdjacencyInput) {
				graph.ReplacePhysicalAdjacencies(PhysicalAdjacencySnapshot{SourceAgent: agent, LocalAddress: local, Adjacencies: adjacencies}, at)
			}
			// core-1 sees dist-2 and the managed device 10.0.0.9; core-2
			// (another agent) also sees shared-5.
			graph.ObserveDevice(DeviceInput{Address: "10.0.0.9", Name: "managed-9"}, t1)
			managed := nbr("agent-a", "", "managed-9")
			managed.RemoteAddress = "10.0.0.9"
			replace("agent-a", "10.0.0.1", t1, nbr("agent-a", "aa:02", "dist-2"), managed, nbr("agent-a", "aa:05", "shared-5"))
			replace("agent-b", "10.0.0.2", t1, nbr("agent-b", "aa:05", "shared-5"))

			// The uplink moves: core-1 now reports dist-3 only.
			replace("agent-a", "10.0.0.1", t2, nbr("agent-a", "aa:03", "dist-3"))
			live := graph.Latest()
			if snapshotHasNode(live, "device:lldp:aa:02") {
				t.Errorf("the live graph still holds dist-2, which core-1 no longer reports: %+v", live.Nodes)
			}
			for _, id := range []string{"device:lldp:aa:03", "device:10.0.0.9", "device:lldp:aa:05", "device:10.0.0.1", "device:10.0.0.2"} {
				if !snapshotHasNode(live, id) {
					t.Errorf("the live graph lost %s, which other evidence keeps current: %+v", id, live.Nodes)
				}
			}
			if !snapshotHasEdge(live, "device:10.0.0.1", "device:lldp:aa:03") || snapshotHasEdge(live, "device:10.0.0.1", "device:lldp:aa:02") {
				t.Errorf("live physical edges = %+v, want core-1 -> dist-3 only", live.Edges)
			}
			if past := graph.SnapshotAt(t1); !snapshotHasNode(past, "device:lldp:aa:02") || !snapshotHasEdge(past, "device:10.0.0.1", "device:lldp:aa:02") {
				t.Errorf("the graph as it was at %s lost dist-2: %+v", t1, past.Nodes)
			}

			// The neighbor coming back makes it current again.
			replace("agent-a", "10.0.0.1", t2.Add(15*time.Second), nbr("agent-a", "aa:02", "dist-2"))
			if live := graph.Latest(); !snapshotHasNode(live, "device:lldp:aa:02") || snapshotHasNode(live, "device:lldp:aa:03") {
				t.Errorf("after dist-2 returns the live nodes are %+v, want dist-2 back and dist-3 gone", live.Nodes)
			}
		})
	}
}

func snapshotHasNode(snapshot Snapshot, id string) bool {
	for _, node := range snapshot.Nodes {
		if node.ID == id {
			return true
		}
	}
	return false
}
