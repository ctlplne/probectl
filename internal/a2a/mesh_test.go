// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package a2a

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/incident"
)

func TestMeshSchedulerThreeSiteFixtureTenantPartitionAndIncidents(t *testing.T) {
	b := NewBroker()
	s := NewMeshScheduler(b)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	b.now = s.now

	agents := []SiteAgent{
		{AgentID: "agent-nyc", Site: "nyc"},
		{AgentID: "agent-sfo", Site: "sfo"},
		{AgentID: "agent-lon", Site: "lon"},
	}
	auditUnavailable := errors.New("audit unavailable")
	if _, err := s.StartMeshAfterAudit("tenant-a", agents, "udp", 4, func(int, string) (map[string]time.Time, error) {
		if _, ok := b.PollFor("tenant-a", "agent-nyc"); ok {
			t.Fatal("a task was dispatched before audit committed")
		}
		return nil, auditUnavailable
	}); !errors.Is(err, auditUnavailable) || b.PendingCount("tenant-a") != 0 || len(s.TopologyOverlay("tenant-a")) != 0 {
		t.Fatal("failed audit left mesh state", err)
	}
	// The PostgreSQL registry and broker have independent clocks. Deliberately
	// put the registration ahead of the broker clock to test exact matching.
	registrations := map[string]time.Time{"agent-nyc": now.Add(time.Second), "agent-sfo": now.Add(-time.Hour), "agent-lon": now.Add(-time.Minute)}
	commit := func(int, string) (map[string]time.Time, error) { return registrations, nil }
	if _, err := s.StartMeshAfterAudit("tenant-replaced", agents, "udp", 4, commit); err != nil {
		t.Fatal(err)
	}
	if task, ok, err := b.PollForWithMeshAdmission("tenant-replaced", "agent-nyc", func() (time.Time, error) {
		return registrations["agent-nyc"].Add(time.Second), nil
	}); err != nil || ok || len(task.MeshResultKey) != 0 {
		t.Fatal("replacement registration received an old assignment", err)
	}
	sessions, err := s.StartMeshAfterAudit("tenant-a", agents, "udp", 4, commit)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 6 {
		t.Fatalf("sessions = %d, want 6 directed site pairs", len(sessions))
	}
	requirePairs(t, sessions, []string{
		"lon->nyc", "lon->sfo", "nyc->lon", "nyc->sfo", "sfo->lon", "sfo->nyc",
	})

	responders := make(map[string]Task)
	initiators := make(map[string]Task)
	poll := func(agent string) (Task, bool) {
		t.Helper()
		task, ok, err := b.PollForWithMeshAdmission("tenant-a", agent, func() (time.Time, error) {
			return registrations[agent], nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return task, ok
	}
	for _, sess := range sessions {
		task, ok := poll(sess.ResponderAgent)
		if !ok || task.SessionID == sess.SessionID || MeshSessionHandle(task.SessionID) != sess.SessionID || task.Role != RoleResponder || task.PeerAgentID != sess.InitiatorAgent {
			t.Fatalf("wrong responder task for %s", sess.SessionID)
		}
		if _, ok := b.PollFor("tenant-b", sess.ResponderAgent); ok {
			t.Fatal("tenant-b saw tenant-a responder task")
		}
		responders[sess.SessionID] = task
	}
	for _, sess := range sessions {
		registration := registrations[sess.ResponderAgent]
		probeSession := responders[sess.SessionID].SessionID
		if err := b.ReportEndpointWithRegistration("tenant-a", sess.ResponderAgent, sess.SessionID, "127.0.0.1", 1234, registration); err == nil {
			t.Fatal("public mesh handle authorized an endpoint report")
		}
		if err := b.ReportEndpointWithRegistration("tenant-a", sess.ResponderAgent, probeSession, "127.0.0.1", 1234, registration.Add(time.Second)); err == nil {
			t.Fatal("replacement responder could announce the prior assignment's endpoint")
		}
		if err := b.ReportEndpointWithRegistration("tenant-a", sess.ResponderAgent, probeSession, "127.0.0.1", 1234, registration); err != nil {
			t.Fatal(err)
		}
		task, ok := poll(sess.InitiatorAgent)
		if !ok || task.SessionID != probeSession || task.Role != RoleInitiator ||
			bytes.Equal(task.MeshResultKey, responders[sess.SessionID].MeshResultKey) {
			t.Fatal("wrong initiator task or reused responder key")
		}
		initiators[sess.SessionID] = task
	}

	store := incident.NewMemoryStore()
	c := incident.NewCorrelator(store, time.Minute, slog.New(slog.NewTextHandler(testWriter{t}, nil)))
	var verifyAfterExpiry func() error
	for _, sess := range sessions {
		lost := sess.FromSite == "nyc" && sess.ToSite == "sfo"
		for _, task := range []Task{initiators[sess.SessionID], responders[sess.SessionID]} {
			agent, peer, role, target := sess.InitiatorAgent, sess.ResponderAgent, "initiator", "127.0.0.1:1234"
			if task.Role == RoleResponder {
				agent, peer, role, target = sess.ResponderAgent, sess.InitiatorAgent, "responder", sess.InitiatorAgent
			}
			wire := meshFixtureResult(sess.TenantID, agent, peer, role, target, now, lost)
			payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			mac := SignMeshResult(task.MeshResultKey, sess.SessionID, payload)
			tampered := bytes.Clone(payload)
			tampered[len(tampered)-1] ^= 1
			claims := []struct {
				tenant, agent string
				body, proof   []byte
			}{
				{"tenant-b", agent, payload, mac}, {sess.TenantID, peer, payload, mac},
				{sess.TenantID, agent, payload, nil}, {sess.TenantID, agent, tampered, mac},
			}
			for _, claim := range claims {
				if _, err := s.VerifyReport(claim.tenant, claim.agent, sess.SessionID, claim.body, claim.proof); !errors.Is(err, ErrInvalidMeshReport) {
					t.Fatal("invalid report was admitted", err)
				}
			}
			wire.Attributes["a2a.role"] = "unassigned"
			spoofed, err := proto.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.VerifyReport(sess.TenantID, agent, sess.SessionID, spoofed,
				SignMeshResult(task.MeshResultKey, sess.SessionID, spoofed)); !errors.Is(err, ErrInvalidMeshReport) {
				t.Fatal("a signed claim of a different role was admitted", err)
			}
			report, err := s.VerifyReport(sess.TenantID, agent, sess.SessionID, payload, mac)
			if err != nil || !report.RegisteredAt.Equal(registrations[agent]) || !s.rememberResult(report.MeshResult) || s.rememberResult(report.MeshResult) {
				t.Fatal("valid report was rejected or duplicated", err)
			}
			if sig, degraded := report.DegradedSignal(); degraded {
				if _, err := c.Ingest(context.Background(), sig); err != nil {
					t.Fatal(err)
				}
			}
			verifyAfterExpiry = func() error {
				_, err := s.VerifyReport(sess.TenantID, agent, sess.SessionID, payload, mac)
				return err
			}
			want := meshStatusHealthy
			if lost {
				want = meshStatusDegraded
			} else if task.Role == RoleInitiator {
				want = meshStatusPending
			}
			if edges := s.RecentTopology(sess.TenantID, sess.SessionID, 1); len(edges) != 1 || edges[0].Status != want {
				t.Fatalf("status = %+v, want %s", edges, want)
			}
		}
	}
	if open, err := store.OpenIncidents(context.Background(), "tenant-a"); err != nil || len(open) != 1 || open[0].SignalCount != 2 {
		t.Fatal("degraded reports did not join one incident", open, err)
	}
	if edges := s.TopologyOverlay("tenant-b"); len(edges) != 0 {
		t.Fatal("sibling tenant saw assigned topology", edges)
	}
	now = now.Add(meshSessionTTL)
	if err := verifyAfterExpiry(); !errors.Is(err, ErrInvalidMeshReport) {
		t.Fatal("an expired assignment admitted a valid old MAC", err)
	}
	if edges := s.TopologyOverlay("tenant-a"); len(edges) != 0 {
		t.Fatal("expired topology is visible", edges)
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

func meshFixtureResult(tenant, agent, peer, role, target string, at time.Time, lost bool) *resultv1.Result {
	loss, received := 0.0, 4.0
	if lost {
		loss, received = 1, 0
	}
	return &resultv1.Result{
		TenantId: tenant, AgentId: agent, CanaryType: "a2a", ServerAddress: target,
		StartTimeUnixNano: at.UnixNano(), DurationNano: int64(time.Millisecond), Success: !lost,
		ResultId: "2da5464a-6102-4e69-be15-b41a640a0296",
		Metrics: map[string]float64{
			"loss.ratio":       loss,
			"packets.sent":     4,
			"packets.received": received,
		},
		Attributes: map[string]string{"a2a.role": role, "a2a.mode": "udp", "network.transport": "udp", "a2a.peer_agent_id": peer},
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
