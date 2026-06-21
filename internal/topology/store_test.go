// SPDX-License-Identifier: LicenseRef-probectl-TBD

package topology

import (
	"errors"
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

func TestTenantStoreBoundary(t *testing.T) {
	at := time.Unix(0, 0)
	for _, tc := range []struct {
		name  string
		store Store
	}{
		{name: "memory", store: NewMemoryStore()},
		{name: "indexed", store: NewIndexedStore()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var deleteGraph func(string) int
			switch s := tc.store.(type) {
			case *MemoryStore:
				deleteGraph = s.DeleteTenant
			case *IndexedStore:
				deleteGraph = s.DeleteTenant
			default:
				t.Fatalf("unexpected store type %T", tc.store)
			}

			for _, tenant := range []string{"", " ", "../tenant-b", "tenant/b", "tenant\x00b"} {
				if _, err := tc.store.ForTenant(tenant); err == nil {
					t.Fatalf("ForTenant(%q) succeeded; want fail closed", tenant)
				} else if strings.TrimSpace(tenant) == "" && !errors.Is(err, ErrNoTenant) {
					t.Fatalf("ForTenant(%q) error = %v, want ErrNoTenant", tenant, err)
				}
			}

			ghost, err := tc.store.ForTenant("never-seen")
			if err != nil {
				t.Fatal(err)
			}
			if snap := ghost.Latest(); snap.Tenant != "never-seen" || len(snap.Nodes) != 0 || len(snap.Edges) != 0 {
				t.Fatalf("empty tenant snapshot = %+v", snap)
			}
			if deleted := deleteGraph("never-seen"); deleted != 0 {
				t.Fatalf("read-only tenant bind created a graph; DeleteTenant returned %d", deleted)
			}

			a, err := tc.store.ForTenant("tenant-a")
			if err != nil {
				t.Fatal(err)
			}
			b, err := tc.store.ForTenant("tenant-b")
			if err != nil {
				t.Fatal(err)
			}
			a.ObserveServiceEdge(ServiceEdgeInput{Source: "a-svc", Destination: "a-db", DestPort: 5432}, at)
			b.ObserveServiceEdge(ServiceEdgeInput{Source: "b-svc", Destination: "b-db", DestPort: 5432}, at)

			aSnap := a.Latest()
			if aSnap.Tenant != "tenant-a" {
				t.Fatalf("tenant-a snapshot tenant = %q", aSnap.Tenant)
			}
			for _, n := range aSnap.Nodes {
				if strings.Contains(n.ID, "b-") {
					t.Fatalf("tenant-a bound handle leaked tenant-b node %q", n.ID)
				}
			}
			if got := a.Traverse("service:b-svc", "service:b-db", at); got != nil {
				t.Fatalf("tenant-a bound handle traversed tenant-b graph: %v", got)
			}
			if got := a.Neighbors("service:b-svc", at); len(got) != 0 {
				t.Fatalf("tenant-a bound handle saw tenant-b neighbors: %v", got)
			}
			if bSnap := b.Latest(); len(bSnap.Nodes) != 2 || len(bSnap.Edges) != 1 {
				t.Fatalf("tenant-b graph damaged or missing: %+v", bSnap)
			}
		})
	}
}
