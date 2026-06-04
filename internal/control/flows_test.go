package control

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
)

// seedFlows loads the server's flow store with two tenants' rows; the second
// tenant's row is the cross-tenant canary that must never appear (the dev-mode
// principal is tenant 00000000-0000-0000-0000-000000000001).
func seedFlows(t *testing.T, s *Server) {
	t.Helper()
	now := time.Now().UTC()
	devTenant := "00000000-0000-0000-0000-000000000001"
	rows := []flowstore.Row{
		{TenantID: devTenant, Exporter: "r1", TS: now.Add(-2 * time.Minute),
			SrcAddr: "10.0.0.1", DstAddr: "10.0.0.9", InIf: 1, BytesScaled: 9000, PacketsScaled: 9,
			SrcASN: 64500, SrcASName: "ACME"},
		{TenantID: devTenant, Exporter: "r1", TS: now.Add(-1 * time.Minute),
			SrcAddr: "10.0.0.2", DstAddr: "10.0.0.9", InIf: 1, BytesScaled: 4000, PacketsScaled: 4},
		{TenantID: "t-other", Exporter: "rX", TS: now.Add(-1 * time.Minute),
			SrcAddr: "172.16.9.9", DstAddr: "172.16.9.8", InIf: 1, BytesScaled: 1 << 40, PacketsScaled: 1},
	}
	if err := s.flowStore.Insert(context.Background(), rows); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// TestFlowTopTalkersAPI: the route serves tenant-scoped, ordered rows and the
// other tenant's traffic never leaks (tenant boundary first — CLAUDE.md §7).
func TestFlowTopTalkersAPI(t *testing.T) {
	srv := testServer(fakePinger{})
	seedFlows(t, srv)

	rec := do(srv, http.MethodGet, "/v1/flows/top?by=src&window=1h&limit=5")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items []flowstore.TopRow `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 2 {
		t.Fatalf("items = %+v, want 2", resp.Items)
	}
	if resp.Items[0].Key != "10.0.0.1" || resp.Items[0].Bytes != 9000 {
		t.Errorf("ordering = %+v", resp.Items)
	}
	for _, r := range resp.Items {
		if r.Key == "172.16.9.9" {
			t.Fatalf("CROSS-TENANT LEAK: %+v", r)
		}
	}
}

// TestFlowCapacityAndAnomalyAPI: both routes answer 200 with items arrays; bad
// params are 400s, not 500s.
func TestFlowCapacityAndAnomalyAPI(t *testing.T) {
	srv := testServer(fakePinger{})
	seedFlows(t, srv)

	rec := do(srv, http.MethodGet, "/v1/flows/capacity?window=1h&bucket=1m&direction=in")
	if rec.Code != http.StatusOK {
		t.Fatalf("capacity status = %d body=%s", rec.Code, rec.Body.String())
	}
	var capResp struct {
		Items []flowstore.CapacityPoint `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &capResp); err != nil || len(capResp.Items) == 0 {
		t.Fatalf("capacity decode: %v items=%d", err, len(capResp.Items))
	}
	if capResp.Items[0].Exporter != "r1" {
		t.Errorf("capacity = %+v", capResp.Items[0])
	}

	rec = do(srv, http.MethodGet, "/v1/flows/anomalies?window=1h&k=3")
	if rec.Code != http.StatusOK {
		t.Fatalf("anomalies status = %d body=%s", rec.Code, rec.Body.String())
	}

	for _, bad := range []string{
		"/v1/flows/top?window=banana",
		"/v1/flows/top?limit=-3",
		"/v1/flows/top?by=bogus",
		"/v1/flows/capacity?direction=sideways",
		"/v1/flows/anomalies?k=-1",
	} {
		rec := do(srv, http.MethodGet, bad)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", bad, rec.Code)
		}
	}
}
