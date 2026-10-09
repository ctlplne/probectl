// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"encoding/json"
	"io"
	"maps"
	"slices"
)

// ExportTenant writes every node and edge of one tenant's graph as JSON Lines,
// in the subject export's record shape ({"kind":"node"|"edge", ...}) and sorted
// by id: the topology plane of the tenant portability bundle. The graph is
// derived from the other planes and bounded, so this is the graph as it
// stands, not its history.
func (s *MemoryStore) ExportTenant(tenant string, w io.Writer) (nodes, edges int64, err error) {
	g, ok := s.graphIfExists(tenant)
	if !ok {
		return 0, 0, nil
	}
	return g.exportAll(w)
}

func (s *IndexedStore) ExportTenant(tenant string, w io.Writer) (nodes, edges int64, err error) {
	g, ok := s.graphIfExists(tenant)
	if !ok {
		return 0, 0, nil
	}
	return g.inner.exportAll(w)
}

func (g *Graph) exportAll(w io.Writer) (nodes, edges int64, err error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	enc := json.NewEncoder(w)
	for _, id := range slices.Sorted(maps.Keys(g.nodes)) {
		node := *g.nodes[id]
		if err := enc.Encode(subjectRecord{Kind: "node", Node: &node}); err != nil {
			return nodes, edges, err
		}
		nodes++
	}
	for _, id := range slices.Sorted(maps.Keys(g.edges)) {
		edge := *g.edges[id]
		if err := enc.Encode(subjectRecord{Kind: "edge", Edge: &edge}); err != nil {
			return nodes, edges, err
		}
		edges++
	}
	return nodes, edges, nil
}
