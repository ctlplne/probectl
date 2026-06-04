package ai

import (
	"context"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/topology"
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
// is tenant-keyed, so the adapter can never return another tenant's graph.
func NewTopologySource(store topology.Store) TopologySource {
	return &topologyAdapter{store: store}
}

type topologyAdapter struct{ store topology.Store }

func (a *topologyAdapter) QueryTopology(_ context.Context, tenant string, q Query) ([]Row, error) {
	at := q.Range.At
	switch {
	case q.From != "" && q.To != "":
		if at.IsZero() {
			at = time.Now()
		}
		var rows []Row
		for i, id := range a.store.Traverse(tenant, q.From, q.To, at) {
			rows = append(rows, Row{"hop": i, "node": id})
		}
		return rows, nil
	case q.NodeID != "":
		if at.IsZero() {
			at = time.Now()
		}
		var rows []Row
		for _, id := range a.store.Neighbors(tenant, q.NodeID, at) {
			rows = append(rows, Row{"neighbor": id})
		}
		return rows, nil
	default:
		snap := a.store.Latest(tenant)
		if !at.IsZero() {
			snap = a.store.SnapshotAt(tenant, at)
		}
		var rows []Row
		for _, n := range snap.Nodes {
			rows = append(rows, Row{"node": n.ID, "kind": string(n.Kind), "label": n.Label})
		}
		return rows, nil
	}
}
