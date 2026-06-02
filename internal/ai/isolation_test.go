package ai

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/topology"
)

// TestQueryLayerCrossTenantIsolation is the S23 security-boundary check: a query
// is incapable of crossing tenants by construction. The tenant comes from the
// principal, never the query, and the tenant-keyed topology store can only return
// the principal's graph. This belongs to the cross-tenant-isolation CI suite.
func TestQueryLayerCrossTenantIsolation(t *testing.T) {
	store := topology.NewMemoryStore()
	at := time.Unix(100, 0)
	store.ObserveServiceEdge("tenant-a", topology.ServiceEdgeInput{Source: "a-frontend", Destination: "a-backend", DestPort: 8443, Transport: "tcp"}, at)
	store.ObserveServiceEdge("tenant-b", topology.ServiceEdgeInput{Source: "b-frontend", Destination: "b-backend", DestPort: 8443, Transport: "tcp"}, at)

	e := NewEngine(WithTopology(NewTopologySource(store)))

	a, err := e.Query(context.Background(), principal("tenant-a", PermTopologyRead), Query{Domain: DomainTopology})
	if err != nil {
		t.Fatal(err)
	}
	if a.Tenant != "tenant-a" {
		t.Errorf("result scope = %q, want tenant-a", a.Tenant)
	}
	for _, row := range a.Rows {
		if node, _ := row["node"].(string); strings.Contains(node, "b-") {
			t.Errorf("tenant-a query returned tenant-b node %q", node)
		}
	}

	b, err := e.Query(context.Background(), principal("tenant-b", PermTopologyRead), Query{Domain: DomainTopology})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range b.Rows {
		if node, _ := row["node"].(string); strings.Contains(node, "a-") {
			t.Errorf("tenant-b query returned tenant-a node %q", node)
		}
	}

	// A's traversal cannot reach B's nodes — the tenant is the principal's and
	// the store is tenant-keyed, so the target simply does not exist in A's graph.
	cross, err := e.Query(context.Background(), principal("tenant-a", PermTopologyRead),
		Query{Domain: DomainTopology, From: "service:a-frontend", To: "service:b-backend", Range: TimeRange{At: at}})
	if err != nil {
		t.Fatal(err)
	}
	if len(cross.Rows) != 0 {
		t.Errorf("tenant-a traverse reached tenant-b: %v", cross.Rows)
	}

	if len(a.Rows) != 2 || len(b.Rows) != 2 {
		t.Errorf("tenant graphs not isolated: a=%d b=%d nodes", len(a.Rows), len(b.Rows))
	}
}
