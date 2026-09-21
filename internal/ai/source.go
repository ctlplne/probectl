// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/topology"
)

// The store sources. Each is tenant-scoped: the engine passes the principal's
// tenant, and a source MUST scope its query to that tenant (the durable backings
// inherit the S2 store-level scoping). Sources never receive a tenant from the
// caller's query.
type MetricsSource interface {
	QueryMetrics(ctx context.Context, tenant string, sel map[string]string, r TimeRange, limit int) ([]Row, error)
}

type EventsSource interface {
	QueryEvents(ctx context.Context, tenant string, sel map[string]string, r TimeRange, limit int) ([]Row, error)
}

type EntitiesSource interface {
	QueryEntities(ctx context.Context, tenant string, sel map[string]string, limit int) ([]Row, error)
}

type TopologySource interface {
	QueryTopology(ctx context.Context, tenant string, q Query) ([]Row, error)
}

// NewTopologySource adapts the S30 topology.Store to a TopologySource. The store
// yields a tenant-bound graph handle, so the adapter can never return another
// tenant's graph after the engine has supplied the principal tenant.
func NewTopologySource(store topology.Store) TopologySource {
	return &topologyAdapter{store: store}
}

type topologyAdapter struct{ store topology.Store }

func (a *topologyAdapter) QueryTopology(_ context.Context, tenant string, q Query) ([]Row, error) {
	graph, err := a.store.ForTenant(tenant)
	if err != nil {
		return nil, err
	}
	at := q.Range.At
	switch {
	case q.From != "" && q.To != "":
		if at.IsZero() {
			at = time.Now()
		}
		var rows []Row
		for i, id := range graph.Traverse(q.From, q.To, at) {
			rows = append(rows, Row{"hop": i, "node": id})
		}
		return rows, nil
	case q.NodeID != "":
		snap := graph.Latest()
		if !at.IsZero() {
			snap = graph.SnapshotAt(at)
		}
		rows := topologyNodeRows(snap, q.NodeID)
		if len(rows) == 0 {
			if at.IsZero() {
				at = time.Now()
			}
			for _, id := range graph.Neighbors(q.NodeID, at) {
				rows = append(rows, Row{"node": q.NodeID, "neighbor": id, "plane": "topology", "title": "topology neighbor " + id})
			}
		}
		return rows, nil
	default:
		snap := graph.Latest()
		if !at.IsZero() {
			snap = graph.SnapshotAt(at)
		}
		var rows []Row
		for _, n := range snap.Nodes {
			rows = append(rows, Row{"node": n.ID, "kind": string(n.Kind), "label": n.Label, "plane": "topology", "title": "topology node " + n.ID})
		}
		return rows, nil
	}
}

func topologyNodeRows(snap topology.Snapshot, nodeID string) []Row {
	var rows []Row
	for _, n := range snap.Nodes {
		if n.ID != nodeID {
			continue
		}
		title := "topology node " + n.ID
		if n.Label != "" {
			title = "topology node " + n.Label
		}
		rows = append(rows, Row{"node": n.ID, "kind": string(n.Kind), "label": n.Label, "plane": "topology", "title": title})
		break
	}
	seen := map[string]bool{}
	for _, e := range snap.Edges {
		if e.From != nodeID && e.To != nodeID {
			continue
		}
		neighbor := e.To
		if e.To == nodeID {
			neighbor = e.From
		}
		key := string(e.Kind) + "|" + neighbor
		if seen[key] {
			continue
		}
		seen[key] = true
		title := "topology " + string(e.Kind) + " " + e.From + " -> " + e.To
		if e.Label != "" {
			title = "topology " + string(e.Kind) + " " + e.Label
		}
		rows = append(rows, Row{"node": nodeID, "neighbor": neighbor, "kind": string(e.Kind), "label": e.Label, "plane": "topology", "title": title})
	}
	return rows
}
