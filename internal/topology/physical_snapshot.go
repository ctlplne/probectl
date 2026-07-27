// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package topology

import "time"

type physicalSnapshotElement struct {
	local  Node
	remote Node
	edge   Edge
}

// ReplacePhysicalAdjacencies applies one complete successful source snapshot.
// Omitted source-owned edges stop appearing in Latest, but their canonical
// records remain available to historical SnapshotAt queries. An edge shared
// by multiple sources remains current until its final owner removes it.
func (g *Graph) ReplacePhysicalAdjacencies(snapshot PhysicalAdjacencySnapshot, at time.Time) {
	if snapshot.SourceAgent == "" || snapshot.LocalAddress == "" || at.IsZero() {
		return
	}
	source := physicalSource{agent: snapshot.SourceAgent, localAddress: snapshot.LocalAddress}
	desired := make(map[string]physicalSnapshotElement, len(snapshot.Adjacencies))
	for _, adjacency := range snapshot.Adjacencies {
		adjacency.SourceAgent = snapshot.SourceAgent
		adjacency.LocalAddress = snapshot.LocalAddress
		local, remote, edge, ok := physicalAdjacencyElements(adjacency)
		if !ok {
			continue
		}
		desired[edge.ID] = physicalSnapshotElement{local: local, remote: remote, edge: edge}
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	previous := g.physicalSources[source]

	for edgeID, element := range desired {
		g.upsertNodeLocked(element.local, at)
		g.upsertNodeLocked(element.remote, at)
		g.upsertEdgeLocked(element.edge, at)
		if g.physicalOwners[edgeID] == nil {
			g.physicalOwners[edgeID] = map[physicalSource]struct{}{}
		}
		g.physicalOwners[edgeID][source] = struct{}{}
		delete(g.physicalRetired, edgeID)
	}
	for edgeID := range previous.edgeIDs {
		if _, stillPresent := desired[edgeID]; stillPresent {
			continue
		}
		delete(g.physicalOwners[edgeID], source)
		if len(g.physicalOwners[edgeID]) == 0 {
			delete(g.physicalOwners, edgeID)
			g.physicalRetired[edgeID] = at
		}
	}

	if len(desired) == 0 {
		delete(g.physicalSources, source)
		return
	}
	next := physicalSourceState{edgeIDs: make(map[string]struct{}, len(desired))}
	for edgeID := range desired {
		next.edgeIDs[edgeID] = struct{}{}
	}
	g.physicalSources[source] = next
}
