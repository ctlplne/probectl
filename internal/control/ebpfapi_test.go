// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/ebpfstore"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

func TestEBPFServiceMapAPIReadsTenantScopedStore(t *testing.T) {
	st := ebpfstore.NewMemory()
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	def := tenancy.DefaultTenantID.String()
	if err := st.Insert(context.Background(), []ebpfstore.Edge{
		{
			TenantID: def, AgentID: "node-1", WindowStart: now,
			SrcWorkload: "checkout", DstWorkload: "payments", DstPort: 8443, L7Protocol: "grpc",
			Bytes: 9000, Packets: 90, Connections: 9,
		},
		{
			TenantID: def, AgentID: "node-2", WindowStart: now,
			SrcWorkload: "api", DstWorkload: "db", DstPort: 5432, L7Protocol: "postgres",
			Bytes: 1000, Packets: 10, Connections: 1,
		},
		{
			TenantID: otherTenant, AgentID: "node-x", WindowStart: now,
			SrcWorkload: "secret", DstWorkload: "vault", DstPort: 443, L7Protocol: "https",
			Bytes: 9999, Packets: 99, Connections: 99,
		},
	}); err != nil {
		t.Fatal(err)
	}
	srv := testServer(fakePinger{}).WithEBPFStore(st)

	rec := do(srv, http.MethodGet, "/v1/ebpf/service-map?source=checkout&limit=5")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items          []ebpfServiceEdgeItem `json:"items"`
		EBPFRunning    bool                  `json:"ebpf_running"`
		Source         string                `json:"source"`
		EffectiveLimit int                   `json:"effective_limit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.EBPFRunning || resp.Source != "store" || resp.EffectiveLimit != 5 || len(resp.Items) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	if got := resp.Items[0]; got.Source != "checkout" || got.Destination != "payments" || got.DestinationPort != 8443 || got.L7Protocol != "grpc" || got.Bytes != 9000 {
		t.Fatalf("service edge = %+v", got)
	}
	if strings.Contains(rec.Body.String(), "secret") || strings.Contains(rec.Body.String(), "vault") {
		t.Fatalf("CROSS-TENANT LEAK: %s", rec.Body.String())
	}
}

func TestEBPFServiceMapAPIFallsBackToTenantTopology(t *testing.T) {
	topo := topology.NewIndexedStore()
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	def := tenancy.DefaultTenantID.String()
	topo.ObserveServiceEdge(def, topology.ServiceEdgeInput{
		Source: "api", Destination: "db", DestPort: 5432, Protocol: "postgres",
	}, now)
	topo.ObserveServiceEdge(otherTenant, topology.ServiceEdgeInput{
		Source: "secret", Destination: "vault", DestPort: 443, Protocol: "https",
	}, now)
	srv := testServer(fakePinger{}).WithTopology(topo)

	rec := do(srv, http.MethodGet, "/v1/ebpf/service-map?src=api&limit=5")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items          []ebpfServiceEdgeItem `json:"items"`
		EBPFRunning    bool                  `json:"ebpf_running"`
		Source         string                `json:"source"`
		EffectiveLimit int                   `json:"effective_limit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.EBPFRunning || resp.Source != "topology" || resp.EffectiveLimit != 5 || len(resp.Items) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	if got := resp.Items[0]; got.Source != "api" || got.Destination != "db" || got.DestinationPort != 5432 || got.L7Protocol != "postgres" {
		t.Fatalf("topology service edge = %+v", got)
	}
	if strings.Contains(rec.Body.String(), "secret") || strings.Contains(rec.Body.String(), "vault") {
		t.Fatalf("CROSS-TENANT LEAK: %s", rec.Body.String())
	}
}
