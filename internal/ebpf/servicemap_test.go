package ebpf

import (
	"testing"
	"time"
)

func TestServiceMapAggregatesDirectedEdges(t *testing.T) {
	m := NewServiceMap()
	base := time.Unix(1000, 0)
	flows := []Flow{
		{TenantID: "t1", Source: Endpoint{Address: "10.0.0.1", Workload: "api"}, Destination: Endpoint{Address: "10.0.0.2", Port: 443, Workload: "db"}, Transport: "tcp", Bytes: 100, Packets: 2, Observed: base},
		{TenantID: "t1", Source: Endpoint{Address: "10.0.0.1", Workload: "api"}, Destination: Endpoint{Address: "10.0.0.2", Port: 443, Workload: "db"}, Transport: "tcp", Bytes: 50, Packets: 1, Observed: base.Add(time.Second)},
		// reverse direction is a DISTINCT edge.
		{TenantID: "t1", Source: Endpoint{Address: "10.0.0.2", Workload: "db"}, Destination: Endpoint{Address: "10.0.0.1", Port: 5432, Workload: "api"}, Transport: "tcp", Observed: base},
	}
	for _, f := range flows {
		m.Observe(f)
	}
	if got := m.Len(); got != 2 {
		t.Fatalf("edges = %d, want 2", got)
	}

	snap := m.Snapshot()
	var apiDB *ServiceEdge
	for i := range snap {
		if snap[i].Source == "api" && snap[i].Destination == "db" {
			apiDB = &snap[i]
		}
	}
	if apiDB == nil {
		t.Fatal("missing api->db edge")
	}
	if apiDB.Connections != 2 || apiDB.Bytes != 150 || apiDB.Packets != 3 {
		t.Errorf("api->db = %+v, want conns=2 bytes=150 packets=3", *apiDB)
	}
	if !apiDB.FirstSeen.Equal(base) || !apiDB.LastSeen.Equal(base.Add(time.Second)) {
		t.Errorf("api->db window = %v..%v, want %v..%v", apiDB.FirstSeen, apiDB.LastSeen, base, base.Add(time.Second))
	}
}

func TestServiceMapNeverMergesAcrossTenants(t *testing.T) {
	m := NewServiceMap()
	tmpl := Flow{Source: Endpoint{Workload: "api"}, Destination: Endpoint{Workload: "db", Port: 443}, Transport: "tcp"}
	a, b := tmpl, tmpl
	a.TenantID, b.TenantID = "t1", "t2"
	m.Observe(a)
	m.Observe(b)
	if m.Len() != 2 {
		t.Fatalf("edges = %d, want 2 (tenant isolation)", m.Len())
	}
	for _, e := range m.Snapshot() {
		if e.Connections != 1 {
			t.Errorf("edge %s->%s (tenant %s) merged across tenants: conns=%d", e.Source, e.Destination, e.TenantID, e.Connections)
		}
	}
}

func TestEndpointIDFallsBackToAddress(t *testing.T) {
	if got := (Endpoint{Address: "1.2.3.4"}).ID(); got != "1.2.3.4" {
		t.Errorf("ID = %q, want address fallback", got)
	}
	if got := (Endpoint{Address: "1.2.3.4", Workload: "api"}).ID(); got != "api" {
		t.Errorf("ID = %q, want workload", got)
	}
}
