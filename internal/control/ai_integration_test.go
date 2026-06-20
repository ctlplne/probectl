// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package control

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/change"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

// aiAnswer mirrors the /v1/ai/ask response for assertions.
type aiAnswer struct {
	ID                   string `json:"id"`
	RootCause            string `json:"root_cause"`
	InsufficientEvidence bool   `json:"insufficient_evidence"`
	Evidence             []struct {
		ID     string `json:"id"`
		Domain string `json:"domain"`
		Plane  string `json:"plane"`
		Title  string `json:"title"`
	} `json:"evidence"`
	Findings []struct {
		Citations []struct {
			EvidenceID string `json:"evidence_id"`
		} `json:"citations"`
	} `json:"findings"`
}

// AIRCA-002: production RCA must gather direct evidence from the promised
// cross-plane source set, not only from incidents and change rows. This seeds
// metrics, flow summaries, BGP-style events, and topology outside any incident,
// then proves /v1/ai/ask cites all four for the asking tenant and none for a
// different tenant.
func TestAIAskUsesDirectCrossPlaneEvidenceSources(t *testing.T) {
	db := changeDB(t)
	tenant := freshTenant(t, db, "airca")
	other := freshTenant(t, db, "airca-other")
	now := time.Now().UTC().Truncate(time.Second)

	metrics := tsdb.NewMemory()
	if err := metrics.Write(context.Background(), []tsdb.Series{
		{Metric: "probectl_probe_loss_ratio", Labels: map[string]string{
			"tenant_id": tenant, "prefix": "192.0.2.0/24", "target": "edge.example.com", "unit": "ratio",
		}, Value: 0.42, TimeMillis: now.Add(-2 * time.Minute).UnixMilli()},
		{Metric: "probectl_probe_loss_ratio", Labels: map[string]string{
			"tenant_id": other, "prefix": "192.0.2.0/24", "target": "should-not-leak.example.com",
		}, Value: 0.99, TimeMillis: now.Add(-2 * time.Minute).UnixMilli()},
	}); err != nil {
		t.Fatal(err)
	}

	flows := flowstore.NewMemory()
	if err := flows.Insert(context.Background(), []flowstore.Row{
		{TenantID: tenant, Exporter: "rr-edge", TS: now.Add(-90 * time.Second),
			SrcAddr: "198.51.100.10", DstAddr: "192.0.2.44", BytesScaled: 90000, PacketsScaled: 900},
		{TenantID: other, Exporter: "rr-other", TS: now.Add(-90 * time.Second),
			SrcAddr: "203.0.113.200", DstAddr: "192.0.2.99", BytesScaled: 1 << 30, PacketsScaled: 1},
	}); err != nil {
		t.Fatal(err)
	}

	topo := topology.NewIndexedStore()
	topo.ObserveRouting(tenant, topology.RoutingInput{
		Prefix: "192.0.2.0/24", OriginASN: 64500, PeerASN: 64496, EventType: "possible_hijack",
	}, now.Add(-3*time.Minute))
	topo.ObserveRouting(other, topology.RoutingInput{
		Prefix: "192.0.2.0/24", OriginASN: 65000, PeerASN: 65001, EventType: "other-tenant",
	}, now.Add(-3*time.Minute))

	seedChange(t, db, tenant, change.Event{
		Source: "bgp", Kind: change.Kind("routing"), Title: "BGP origin changed for 192.0.2.0/24",
		Summary: "unexpected origin AS64500", Prefix: "192.0.2.0/24", OccurredAt: now.Add(-4 * time.Minute),
	})

	cfg := &config.Config{HSTSEnabled: true, HSTSMaxAge: time.Hour, AuthMode: "dev", AIMaxEvidence: 50}
	srv := New(cfg, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil).
		WithTSDB(metrics).
		WithFlowStore(flows).
		WithTopology(topo)

	rec := apiReq(t, srv.Handler(), http.MethodPost, "/v1/ai/ask", tenant, map[string]any{
		"question": "why is 192.0.2.0/24 slow and unreachable? check bgp route, flow, topology, and metrics",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("ask: status %d body %s", rec.Code, rec.Body)
	}
	var ans aiAnswer
	mustJSON(t, rec, &ans)
	if ans.InsufficientEvidence {
		t.Fatalf("expected direct evidence, got insufficient: %+v", ans)
	}
	planes := map[string]bool{}
	titles := []string{}
	for _, e := range ans.Evidence {
		planes[e.Plane] = true
		titles = append(titles, e.Title)
	}
	for _, want := range []string{"metrics", "bgp", "flow", "topology"} {
		if !planes[want] {
			t.Fatalf("missing %s evidence; planes=%v titles=%v body=%s", want, planes, titles, rec.Body.String())
		}
	}
	if strings.Contains(rec.Body.String(), "should-not-leak") || strings.Contains(rec.Body.String(), "203.0.113.200") {
		t.Fatalf("cross-tenant evidence leaked: %s", rec.Body.String())
	}

	rec = apiReq(t, srv.Handler(), http.MethodPost, "/v1/ai/ask", other, map[string]any{
		"question": "why is 198.51.100.0/24 slow and unreachable? check bgp route, flow, topology, and metrics",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("other ask: status %d body %s", rec.Code, rec.Body)
	}
	var otherAns aiAnswer
	mustJSON(t, rec, &otherAns)
	for _, e := range otherAns.Evidence {
		if strings.Contains(e.Title, "192.0.2.0/24") {
			t.Fatalf("other tenant saw tenant evidence: %+v", otherAns)
		}
	}
}

// End-to-end RCA against Postgres (S24 Done-when): a critical BGP incident for
// tenant A becomes cited evidence in a grounded answer; every finding resolves to
// real evidence (citation integrity); feedback persists; and tenant B — with no
// such incident — gets an insufficient-evidence answer, proving the assistant is
// tenant-scoped via the S23 boundary (it never sees another tenant's signals).
func TestAIAskGroundedCitedAndTenantScoped(t *testing.T) {
	h, db := setupAPI(t)
	c := BuildCorrelator(db.Pool(), 5*time.Minute, quietLog())
	ctx := context.Background()
	// A fresh tenant isolates this test's incident from the shared integration DB
	// (the default tenant's incidents are asserted on by TestIncidentCorrelationAndAPI).
	tnA, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("aimain-%d", time.Now().UnixNano()), "AI Main")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tenant := tnA.ID
	now := time.Now().UTC().Truncate(time.Second)

	if _, err := c.Ingest(ctx, incident.Signal{
		TenantID: tenant, Plane: "bgp", Kind: "bgp.possible_hijack", Severity: incident.SeverityCritical,
		Title: "possible hijack 192.0.2.0/24", Target: "192.0.2.0/24", Prefix: "192.0.2.0/24", OccurredAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Tenant A: a grounded, cited root cause naming the routing event.
	rec := apiReq(t, h, http.MethodPost, "/v1/ai/ask", tenant, map[string]any{
		"question": "why is 192.0.2.0/24 unreachable? any routing changes?",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("ask: status %d body %s", rec.Code, rec.Body)
	}
	var ans aiAnswer
	mustJSON(t, rec, &ans)
	if ans.InsufficientEvidence || len(ans.Evidence) == 0 {
		t.Fatalf("expected a grounded answer, got %+v", ans)
	}
	if !strings.Contains(strings.ToLower(ans.RootCause), "hijack") {
		t.Errorf("root cause should name the routing signal, got %q", ans.RootCause)
	}
	ids := map[string]bool{}
	for _, e := range ans.Evidence {
		ids[e.ID] = true
	}
	for _, f := range ans.Findings {
		for _, cit := range f.Citations {
			if !ids[cit.EvidenceID] {
				t.Errorf("finding cites missing evidence %q (citation integrity)", cit.EvidenceID)
			}
		}
	}

	// Feedback persists, tenant-scoped → 204.
	if rec := apiReq(t, h, http.MethodPost, "/v1/ai/feedback", tenant, map[string]any{
		"answer_id": ans.ID, "rating": "up", "comment": "spot on",
	}); rec.Code != http.StatusNoContent {
		t.Errorf("feedback: status %d body %s", rec.Code, rec.Body)
	}

	// Tenant B has no such incident → insufficient evidence (tenant isolation:
	// the assistant cannot see tenant A's signals).
	tn, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("aiiso-%d", time.Now().UnixNano()), "AI Isolation")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	rec = apiReq(t, h, http.MethodPost, "/v1/ai/ask", tn.ID, map[string]any{
		"question": "why is 192.0.2.0/24 unreachable? any routing changes?",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant B ask: status %d body %s", rec.Code, rec.Body)
	}
	var bAns aiAnswer
	mustJSON(t, rec, &bAns)
	if !bAns.InsufficientEvidence || len(bAns.Evidence) != 0 {
		t.Errorf("tenant B must not see tenant A's incident; got %+v", bAns)
	}
}
