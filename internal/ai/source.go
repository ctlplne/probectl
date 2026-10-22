// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"net/netip"
	"slices"
	"strings"
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
		var rows []Row
		seen := map[string]bool{}
		for _, anchor := range topologyAnchors(snap, q) {
			for _, row := range topologyNodeRows(snap, anchor) {
				key := rowString(row, "node") + "|" + rowString(row, "kind") + "|" + rowString(row, "neighbor")
				if !seen[key] {
					seen[key] = true
					rows = append(rows, row)
				}
			}
		}
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

// maxContainingPrefixes bounds how many routing prefixes an address subject
// anchors on: the most specific blocks holding it, never the whole table.
const maxContainingPrefixes = 4

// topologyAnchors resolves where a question touches the tenant's graph
// (DPR-299). An explicit node subject is that node alone. An address subject
// — the host or IP a question names, which the planner can only phrase as a
// service — is every node the graph keys by that address: the eBPF service,
// the path target, the traceroute hop and the managed device. It is also the
// prefix nodes whose block holds the address, so the walk reaches from a
// failing host to the routing origin that carries it, the way the correlator
// joins a host's alert to its prefix's incident. A prefix subject is that
// prefix. Only anchors present in the snapshot are kept, in that order.
func topologyAnchors(snap topology.Snapshot, q Query) []string {
	present := make(map[string]bool, len(snap.Nodes))
	for _, n := range snap.Nodes {
		present[n.ID] = true
	}
	var out []string
	add := func(id string) {
		if present[id] && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	add(q.NodeID)
	if q.Selector["node"] != "" {
		return out
	}
	if target := q.Selector["target"]; target != "" {
		for _, kind := range []string{"service:", "host:", "hop:", "device:"} {
			add(kind + target)
		}
		if addr, err := netip.ParseAddr(target); err == nil {
			for _, id := range containingPrefixes(snap, addr) {
				add(id)
			}
		}
	}
	if prefix := q.Selector["prefix"]; prefix != "" {
		add("prefix:" + prefix)
	}
	return out
}

// containingPrefixes lists the prefix nodes whose block holds addr, most
// specific first, bounded by maxContainingPrefixes.
func containingPrefixes(snap topology.Snapshot, addr netip.Addr) []string {
	type match struct {
		id   string
		bits int
	}
	var found []match
	for _, n := range snap.Nodes {
		if n.Kind != topology.NodePrefix {
			continue
		}
		p, err := netip.ParsePrefix(strings.TrimPrefix(n.ID, "prefix:"))
		if err != nil || !p.Contains(addr) {
			continue
		}
		found = append(found, match{id: n.ID, bits: p.Bits()})
	}
	slices.SortFunc(found, func(a, b match) int {
		if a.bits != b.bits {
			return b.bits - a.bits
		}
		return strings.Compare(a.id, b.id)
	})
	out := make([]string, 0, min(len(found), maxContainingPrefixes))
	for i := 0; i < len(found) && i < maxContainingPrefixes; i++ {
		out = append(out, found[i].id)
	}
	return out
}

func rowString(row Row, key string) string {
	v, _ := row[key].(string)
	return v
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
