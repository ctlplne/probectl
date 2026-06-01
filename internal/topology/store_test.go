package topology

import (
	"strings"
	"testing"
	"time"
)

func TestMemoryStoreTenantIsolation(t *testing.T) {
	s := NewMemoryStore()
	at := time.Unix(0, 0)
	s.ObserveServiceEdge("tenant-a", ServiceEdgeInput{Source: "a-svc", Destination: "a-db", DestPort: 5432, Transport: "tcp"}, at)
	s.ObserveServiceEdge("tenant-b", ServiceEdgeInput{Source: "b-svc", Destination: "b-db", DestPort: 5432, Transport: "tcp"}, at)

	a := s.Latest("tenant-a")
	if a.Tenant != "tenant-a" {
		t.Errorf("snapshot tenant = %q, want tenant-a", a.Tenant)
	}
	for _, n := range a.Nodes {
		if strings.Contains(n.ID, "b-") {
			t.Errorf("tenant-a graph leaked tenant-b node %q", n.ID)
		}
	}
	// A tenant can never traverse into another tenant's graph.
	if p := s.Traverse("tenant-b", "service:a-svc", "service:a-db", at); p != nil {
		t.Errorf("tenant-b traverse reached tenant-a nodes: %v", p)
	}
	if len(a.Nodes) != 2 || len(s.Latest("tenant-b").Nodes) != 2 {
		t.Errorf("tenant graphs are not isolated by size: a=%d b=%d", len(a.Nodes), len(s.Latest("tenant-b").Nodes))
	}
}
