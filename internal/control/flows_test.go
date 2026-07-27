// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/flow"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
)

type captureFlowQualityStore struct {
	filter  flow.QualityFilter
	receipt flow.QualityReceipt
}

func (s *captureFlowQualityStore) UpsertQualityReceipt(context.Context, string, flow.QualityReceipt) error {
	return nil
}

func (s *captureFlowQualityStore) ListQualityReceipts(_ context.Context, _ string, filter flow.QualityFilter) ([]flow.QualityReceipt, bool, error) {
	s.filter = filter
	receipt := flow.EvaluateQualityState(s.receipt, filter.AsOf)
	if filter.State != "" && receipt.State != filter.State {
		return []flow.QualityReceipt{}, false, nil
	}
	return []flow.QualityReceipt{receipt}, false, nil
}

// seedFlows loads the server's flow store with two tenants' rows; the second
// tenant's row is the cross-tenant canary that must never appear (the dev-mode
// principal is tenant 00000000-0000-0000-0000-000000000001).
func seedFlows(t *testing.T, s *Server) {
	t.Helper()
	now := time.Now().UTC()
	devTenant := "00000000-0000-0000-0000-000000000001"
	rows := []flowstore.Row{
		{TenantID: devTenant, Exporter: "r1", Protocol: "netflow5", TS: now.Add(-2 * time.Minute),
			SrcAddr: "10.0.0.1", DstAddr: "10.0.0.9", InIf: 1, BytesScaled: 9000, PacketsScaled: 9,
			SrcASN: 64500, SrcASName: "ACME", SrcCountry: "US", DstCountry: "DE", DstPort: 443},
		{TenantID: devTenant, Exporter: "r1", Protocol: "ipfix", TS: now.Add(-1 * time.Minute),
			SrcAddr: "10.0.0.2", DstAddr: "10.0.0.9", InIf: 1, BytesScaled: 4000, PacketsScaled: 4,
			SrcCountry: "CA", DstCountry: "DE", DstPort: 53},
		{TenantID: "t-other", Exporter: "rX", Protocol: "netflow5", TS: now.Add(-1 * time.Minute),
			SrcAddr: "172.16.9.9", DstAddr: "172.16.9.8", InIf: 1, BytesScaled: 1 << 40, PacketsScaled: 1,
			SrcCountry: "US", DstCountry: "DE", DstPort: 443},
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

	rec := do(srv, http.MethodGet, "/v1/flows/top?by=src&window=1h&bucket=1m&limit=5")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items   []flowstore.TopRow      `json:"items"`
		Series  []flowstore.SeriesPoint `json:"series"`
		Filters []flowstore.Filter      `json:"filters"`
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
	if len(resp.Series) != 2 {
		t.Fatalf("series = %+v, want two tenant-local buckets", resp.Series)
	}
	for _, point := range resp.Series {
		if point.Key == "172.16.9.9" {
			t.Fatalf("CROSS-TENANT SERIES LEAK: %+v", point)
		}
	}

	rec = do(srv, http.MethodGet, "/v1/flows/top?by=dst_country&filter=protocol:netflow5&filter=port:443")
	if rec.Code != http.StatusOK {
		t.Fatalf("filtered status = %d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("filtered decode: %v", err)
	}
	if len(resp.Items) != 1 || resp.Items[0].Key != "DE" || resp.Items[0].Bytes != 9000 {
		t.Fatalf("filtered items = %+v", resp.Items)
	}
	if len(resp.Filters) != 2 || resp.Filters[0].Field != flowstore.FilterProtocol {
		t.Fatalf("effective filters = %+v", resp.Filters)
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
		"/v1/flows/top?filter=tenant_id:t-other",
		"/v1/flows/top?filter=port:70000",
		"/v1/flows/top?filter=missing-colon",
		"/v1/flows/capacity?direction=sideways",
		"/v1/flows/anomalies?k=-1",
	} {
		rec := do(srv, http.MethodGet, bad)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", bad, rec.Code)
		}
	}
}

func TestFlowIngestQualityAPITenantScopedVersionedAndRedacted(t *testing.T) {
	store := flow.NewMemoryQualityStore()
	now := time.Now().UTC().Truncate(time.Second)
	write := func(tenant, agent, exporter string) {
		t.Helper()
		last := now.Add(-time.Second)
		receipt := flow.EvaluateQualityState(flow.QualityReceipt{
			TenantID: tenant, AgentID: agent, ExporterAddress: exporter,
			Protocol: flow.ProtoIPFIX, WindowStartedAt: now.Add(-time.Minute),
			WindowEndedAt: now, LastPacketAt: last, LastValidRecordAt: &last,
			PacketsReceived: 10, RecordsDecoded: 20,
			TemplateState: flow.QualityTemplateReady,
			SamplingState: flow.QualitySamplingSampled,
		}, now)
		if err := store.UpsertQualityReceipt(context.Background(), tenant, receipt); err != nil {
			t.Fatal(err)
		}
	}
	const tenantA = "00000000-0000-0000-0000-000000000001"
	write(tenantA, "agent-a", "192.0.2.10")
	write("00000000-0000-0000-0000-000000000002", "agent-secret", "198.51.100.20")
	srv := testServer(fakePinger{}).WithFlowQualityReceipts(store)
	rec := do(srv, http.MethodGet, "/v1/flows/ingest-quality?limit=10&protocol=ipfix")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp flowQualityResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ContractVersion != flow.QualityContractVersion || !resp.IngestRunning ||
		len(resp.Items) != 1 || resp.Items[0].ExporterAddress != "192.0.2.10" {
		t.Fatalf("response=%+v", resp)
	}
	body := rec.Body.String()
	for _, forbidden := range []string{
		"198.51.100.20", "agent-secret", "tenant_id", "raw_datagram",
		"source_address", "destination_address", "credential", "error_text",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response retained forbidden/cross-tenant field %q: %s", forbidden, body)
		}
	}
	for _, path := range []string{
		"/v1/flows/ingest-quality?state=unknown",
		"/v1/flows/ingest-quality?protocol=snmp",
		"/v1/flows/ingest-quality?exporter=router.internal",
	} {
		if got := do(srv, http.MethodGet, path).Code; got != http.StatusBadRequest {
			t.Fatalf("%s status=%d, want 400", path, got)
		}
	}
}

func TestFlowIngestQualityAPIUsesResponseAsOfForStateFilter(t *testing.T) {
	last := time.Date(2020, 1, 1, 2, 0, 0, 0, time.UTC)
	store := &captureFlowQualityStore{
		receipt: flow.QualityReceipt{
			AgentID: "agent-a", ExporterAddress: "192.0.2.10", Protocol: flow.ProtoIPFIX,
			WindowStartedAt: last.Add(-time.Minute), WindowEndedAt: last,
			LastPacketAt: last, LastValidRecordAt: &last,
			PacketsReceived: 1, RecordsDecoded: 1,
			TemplateState: flow.QualityTemplateReady,
			SamplingState: flow.QualitySamplingUnsampled,
		},
	}
	rec := do(
		testServer(fakePinger{}).WithFlowQualityReceipts(store),
		http.MethodGet,
		"/v1/flows/ingest-quality?state=stale",
	)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp flowQualityResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if store.filter.AsOf.IsZero() || !resp.AsOf.Equal(store.filter.AsOf) {
		t.Fatalf("response as_of=%s store as_of=%s", resp.AsOf, store.filter.AsOf)
	}
	if len(resp.Items) != 1 || resp.Items[0].State != flow.QualityStateStale {
		t.Fatalf("state-filtered response=%+v", resp)
	}
}

func TestFlowIngestQualityAPIReportsUnwiredHonestly(t *testing.T) {
	rec := do(testServer(fakePinger{}), http.MethodGet, "/v1/flows/ingest-quality")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp flowQualityResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.IngestRunning || len(resp.Items) != 0 {
		t.Fatalf("unwired response=%+v", resp)
	}
}
