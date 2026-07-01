// SPDX-License-Identifier: LicenseRef-probectl-TBD

package a2a

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/canary"
	"github.com/imfeelingtheagi/probectl/internal/incident"
)

func TestMeshSchedulerThreeSiteFixtureTenantPartitionAndIncidents(t *testing.T) {
	b := NewBroker()
	s := NewMeshScheduler(b)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	agents := []SiteAgent{
		{AgentID: "agent-nyc", Site: "nyc"},
		{AgentID: "agent-sfo", Site: "sfo"},
		{AgentID: "agent-lon", Site: "lon"},
	}
	sessions, err := s.StartMesh("tenant-a", agents, "udp", 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 6 {
		t.Fatalf("sessions = %d, want 6 directed site pairs", len(sessions))
	}
	requirePairs(t, sessions, []string{
		"lon->nyc", "lon->sfo", "nyc->lon", "nyc->sfo", "sfo->lon", "sfo->nyc",
	})

	for _, sess := range sessions {
		task, ok := b.PollFor("tenant-a", sess.ResponderAgent)
		if !ok {
			t.Fatalf("responder %s had no broker task for %s", sess.ResponderAgent, sess.SessionID)
		}
		if task.SessionID != sess.SessionID || task.Role != RoleResponder || task.PeerAgentID != sess.InitiatorAgent {
			t.Fatalf("task = %+v, session = %+v", task, sess)
		}
		if _, ok := b.PollFor("tenant-b", sess.ResponderAgent); ok {
			t.Fatalf("tenant-b saw tenant-a responder task for %s", sess.ResponderAgent)
		}
	}

	var degraded MeshSession
	for _, sess := range sessions {
		success := true
		loss := 0.0
		if sess.FromSite == "nyc" && sess.ToSite == "sfo" {
			degraded = sess
			success = false
			loss = 1
		}
		if _, err := s.RecordResult("tenant-a", sess.SessionID, sess.InitiatorAgent, meshCanaryResult("initiator", success, loss, now)); err != nil {
			t.Fatalf("record initiator result: %v", err)
		}
	}
	if degraded.SessionID == "" {
		t.Fatal("test fixture did not find nyc->sfo session")
	}
	if _, err := s.RecordResult("tenant-a", degraded.SessionID, degraded.ResponderAgent, meshCanaryResult("responder", false, 1, now.Add(time.Second))); err != nil {
		t.Fatalf("record responder degraded result: %v", err)
	}
	if _, err := s.RecordResult("tenant-b", degraded.SessionID, degraded.InitiatorAgent, meshCanaryResult("initiator", true, 0, now)); err == nil {
		t.Fatal("cross-tenant result write must fail closed")
	}

	if got := len(s.Results("tenant-a")); got != 7 {
		t.Fatalf("tenant-a results = %d, want 7", got)
	}
	if got := len(s.Results("tenant-b")); got != 0 {
		t.Fatalf("tenant-b results = %d, want 0", got)
	}

	edges := s.TopologyOverlay("tenant-a")
	if len(edges) != 6 {
		t.Fatalf("topology edges = %d, want 6", len(edges))
	}
	statuses := map[string]string{}
	for _, e := range edges {
		statuses[e.FromSite+"->"+e.ToSite] = e.Status
	}
	if statuses["nyc->sfo"] != meshStatusDegraded {
		t.Fatalf("nyc->sfo status = %q, want degraded", statuses["nyc->sfo"])
	}
	if statuses["sfo->nyc"] != meshStatusHealthy {
		t.Fatalf("sfo->nyc status = %q, want healthy", statuses["sfo->nyc"])
	}

	store := incident.NewMemoryStore()
	c := incident.NewCorrelator(store, time.Minute, slog.New(slog.NewTextHandler(testWriter{t}, nil)))
	for _, sig := range s.IncidentSignals("tenant-a") {
		if _, err := c.Ingest(context.Background(), sig); err != nil {
			t.Fatal(err)
		}
	}
	if store.Len() != 1 {
		t.Fatalf("tenant-a incidents = %d, want 1 correlated incident", store.Len())
	}
	open, err := store.OpenIncidents(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].SignalCount != 2 {
		t.Fatalf("tenant-a open incidents = %+v, want one incident with two signals", open)
	}

	tenantB, err := s.StartMesh("tenant-b", agents, "udp", 4)
	if err != nil {
		t.Fatal(err)
	}
	var tenantBDegraded MeshSession
	for _, sess := range tenantB {
		if sess.FromSite == "nyc" && sess.ToSite == "sfo" {
			tenantBDegraded = sess
			break
		}
	}
	if _, err := s.RecordResult("tenant-b", tenantBDegraded.SessionID, tenantBDegraded.InitiatorAgent, meshCanaryResult("initiator", false, 1, now)); err != nil {
		t.Fatal(err)
	}
	for _, sig := range s.IncidentSignals("tenant-b") {
		if _, err := c.Ingest(context.Background(), sig); err != nil {
			t.Fatal(err)
		}
	}
	if store.Len() != 2 {
		t.Fatalf("incidents across tenants = %d, want 2 tenant-partitioned incidents", store.Len())
	}
}

func TestMeshSchedulerValidation(t *testing.T) {
	s := NewMeshScheduler(NewBroker())
	if _, err := s.StartMesh("", nil, "udp", 1); err == nil {
		t.Fatal("missing tenant should error")
	}
	if _, err := s.StartMesh("tenant-a", []SiteAgent{{AgentID: "a", Site: "nyc"}}, "udp", 1); err == nil {
		t.Fatal("single-site mesh should error")
	}
	if _, err := s.StartMesh("tenant-a", []SiteAgent{{AgentID: "a", Site: "nyc"}, {AgentID: "b", Site: "sfo"}}, "icmp", 1); err == nil {
		t.Fatal("unsupported mode should error")
	}
}

func requirePairs(t *testing.T, sessions []MeshSession, want []string) {
	t.Helper()
	got := map[string]bool{}
	for _, sess := range sessions {
		got[sess.FromSite+"->"+sess.ToSite] = true
	}
	for _, pair := range want {
		if !got[pair] {
			t.Fatalf("missing pair %s from sessions %#v", pair, sessions)
		}
	}
}

func meshCanaryResult(role string, success bool, loss float64, at time.Time) canary.Result {
	return canary.Result{
		Type:      "a2a",
		Target:    "peer",
		Success:   success,
		StartedAt: at,
		Metrics: map[string]float64{
			"loss.ratio":       loss,
			"packets.sent":     4,
			"packets.received": 4 * (1 - loss),
		},
		Attributes: map[string]string{"a2a.role": role},
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
