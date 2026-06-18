// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/change"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/notify"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// U-057: integration coverage for the store paths the original suite skipped —
// agents, incidents, change events, alert rules, synthetic tests, AI feedback/
// answers, MCP + SCIM tokens, SIEM cursor, and incident-integration links —
// all against the real schema (RLS included), via the same setup/skip harness.

func TestAgentsRegistry(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("ag-%d", time.Now().UnixNano()), "Agents")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// agents.id is a uuid column; mint a unique v4 UUID per run (global PK).
	agentID := fmt.Sprintf("a8000000-0000-4000-8000-%012x", time.Now().UnixNano()&0xffffffffffff)
	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		spiffe := "spiffe://probectl/tenant/" + tn.ID + "/agent/" + agentID
		a, err := (Agents{}).Register(ctx, s, agentID, "edge-1", "host-1", "1.0.0", spiffe, []string{"icmp", "tcp"})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		if a.ID != agentID {
			t.Fatalf("registered id = %q", a.ID)
		}
		// Re-register = idempotent upsert (new version sticks).
		if _, err := (Agents{}).Register(ctx, s, agentID, "edge-1", "host-1", "1.1.0", spiffe, []string{"icmp"}); err != nil {
			t.Fatalf("re-register: %v", err)
		}
		if hb, err := (Agents{}).Heartbeat(ctx, s, agentID); err != nil || hb == nil {
			t.Fatalf("heartbeat: %v", err)
		}
		if got, err := (Agents{}).Get(ctx, s, agentID); err != nil || got.AgentVersion != "1.1.0" {
			t.Fatalf("get after upsert: %v / %+v", err, got)
		}
		if ren, err := (Agents{}).Rename(ctx, s, agentID, "edge-renamed"); err != nil || ren.Name != "edge-renamed" {
			t.Fatalf("rename: %v / %+v", err, ren)
		}
		if list, err := (Agents{}).List(ctx, s); err != nil || len(list) != 1 {
			t.Fatalf("list: %v / %d", err, len(list))
		}
		if err := (Agents{}).Delete(ctx, s, agentID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if list, err := (Agents{}).List(ctx, s); err != nil || len(list) != 0 {
			t.Fatalf("list after delete: %v / %d", err, len(list))
		}
		return nil
	})
}

func TestIncidentLifecycle(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("inc-%d", time.Now().UnixNano()), "Incidents")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		now := time.Now().UTC()
		inc, err := (Incidents{}).Create(ctx, s, incident.Incident{
			TenantID: tn.ID, Status: incident.StatusOpen, Severity: incident.SeverityCritical,
			Title: "checkout degraded", Target: "checkout", StartedAt: now, LastSeenAt: now,
		})
		if err != nil {
			t.Fatalf("create incident: %v", err)
		}
		if _, err := (Incidents{}).AppendSignal(ctx, s, inc.ID, incident.Signal{
			TenantID: tn.ID, Plane: "bgp", Kind: "bgp.withdrawal", Severity: incident.SeverityCritical,
			Title: "route withdrawn", Target: "checkout", OccurredAt: now,
		}); err != nil {
			t.Fatalf("append signal: %v", err)
		}
		full, err := (Incidents{}).Get(ctx, s, inc.ID)
		if err != nil || full == nil {
			t.Fatalf("get: %v", err)
		}
		if len(full.Signals) != 1 || full.Signals[0].Plane != "bgp" {
			t.Fatalf("signals = %+v", full.Signals)
		}
		if open, err := (Incidents{}).OpenIncidents(ctx, s); err != nil || len(open) != 1 {
			t.Fatalf("open incidents: %v / %d", err, len(open))
		}
		if res, err := (Incidents{}).Resolve(ctx, s, inc.ID); err != nil || res.ResolvedAt == nil {
			t.Fatalf("resolve: %v / %+v", err, res)
		}
		if open, err := (Incidents{}).OpenIncidents(ctx, s); err != nil || len(open) != 0 {
			t.Fatalf("open after resolve: %v / %d", err, len(open))
		}
		if all, err := (Incidents{}).List(ctx, s); err != nil || len(all) != 1 {
			t.Fatalf("list: %v / %d", err, len(all))
		}
		return nil
	})
}

func TestChangeEventsStore(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("chg-%d", time.Now().UnixNano()), "Changes")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		old := time.Now().UTC().Add(-2 * time.Hour)
		recent := time.Now().UTC().Add(-5 * time.Minute)
		if _, err := (ChangeEvents{}).Create(ctx, s, change.Event{
			TenantID: tn.ID, Source: "generic", Kind: change.Kind("deploy"),
			Title: "old deploy", Target: "svc-a", OccurredAt: old,
		}); err != nil {
			t.Fatalf("create old: %v", err)
		}
		if _, err := (ChangeEvents{}).Create(ctx, s, change.Event{
			TenantID: tn.ID, Source: "generic", Kind: change.Kind("deploy"),
			Title: "recent deploy", Target: "svc-a", Actor: "ci", Ref: "abc123", OccurredAt: recent,
		}); err != nil {
			t.Fatalf("create recent: %v", err)
		}
		if all, err := (ChangeEvents{}).List(ctx, s, 10); err != nil || len(all) != 2 {
			t.Fatalf("list: %v / %d", err, len(all))
		}
		since, err := (ChangeEvents{}).Since(ctx, s, time.Now().UTC().Add(-time.Hour), 10)
		if err != nil || len(since) != 1 || since[0].Title != "recent deploy" {
			t.Fatalf("since: %v / %+v", err, since)
		}
		return nil
	})
}

func TestAlertRulesCRUD(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("alr-%d", time.Now().UnixNano()), "Alerts")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		r, err := (AlertRules{}).Create(ctx, s, alert.Rule{
			TenantID: tn.ID, Name: "latency-high", Enabled: true,
			Metric: "probe.rtt.ms", Match: map[string]string{"target": "svc-a"},
			Type: alert.Threshold, Comparison: alert.GT, Threshold: 200,
			Severity: alert.SeverityCritical,
		})
		if err != nil {
			t.Fatalf("create rule: %v", err)
		}
		if got, err := (AlertRules{}).Get(ctx, s, r.ID); err != nil || got.Name != "latency-high" {
			t.Fatalf("get: %v / %+v", err, got)
		}
		if list, err := (AlertRules{}).List(ctx, s); err != nil || len(list) != 1 {
			t.Fatalf("list: %v / %d", err, len(list))
		}
		if enabled, err := (AlertRules{}).ListEnabled(ctx, s); err != nil || len(enabled) != 1 {
			t.Fatalf("list enabled: %v / %d", err, len(enabled))
		}
		upd := *r
		upd.Enabled = false
		upd.Threshold = 500
		if got, err := (AlertRules{}).Update(ctx, s, r.ID, upd); err != nil || got.Threshold != 500 || got.Enabled {
			t.Fatalf("update: %v / %+v", err, got)
		}
		if enabled, err := (AlertRules{}).ListEnabled(ctx, s); err != nil || len(enabled) != 0 {
			t.Fatalf("list enabled after disable: %v / %d", err, len(enabled))
		}
		if err := (AlertRules{}).Delete(ctx, s, r.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if list, err := (AlertRules{}).List(ctx, s); err != nil || len(list) != 0 {
			t.Fatalf("list after delete: %v / %d", err, len(list))
		}
		return nil
	})
}

func TestSyntheticTestsCRUD(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("tst-%d", time.Now().UnixNano()), "Tests")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		in := TestInput{Name: "ping-a", Type: "icmp", Target: "203.0.113.10",
			IntervalSeconds: 60, TimeoutSeconds: 5, Params: map[string]string{"count": "3"}, Enabled: true}
		tt, err := (Tests{}).Create(ctx, s, in)
		if err != nil {
			t.Fatalf("create test: %v", err)
		}
		if got, err := (Tests{}).Get(ctx, s, tt.ID); err != nil || got.Name != "ping-a" || got.Params["count"] != "3" {
			t.Fatalf("get: %v / %+v", err, got)
		}
		in.Name = "ping-b"
		in.Enabled = false
		if got, err := (Tests{}).Update(ctx, s, tt.ID, in); err != nil || got.Name != "ping-b" || got.Enabled {
			t.Fatalf("update: %v / %+v", err, got)
		}
		if list, err := (Tests{}).List(ctx, s); err != nil || len(list) != 1 {
			t.Fatalf("list: %v / %d", err, len(list))
		}
		if err := (Tests{}).Delete(ctx, s, tt.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if got, _ := (Tests{}).Get(ctx, s, tt.ID); got != nil {
			t.Fatalf("get after delete should be nil, got %+v", got)
		}
		return nil
	})
}

func TestAIFeedbackAndAnswers(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("aif-%d", time.Now().UnixNano()), "AI")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		if err := (AIFeedback{}).Save(ctx, s, AIFeedbackInput{
			AnswerID: "ans-1", Question: "why down", Rating: "up", Comment: "good", UserID: "u1",
		}); err != nil {
			t.Fatalf("save feedback: %v", err)
		}
		// U-093: persisted answer artifact — idempotent save + retention prune.
		in := AIAnswerInput{AnswerID: "ans-1", Question: "why down", RootCause: "deploy X",
			Confidence: "high", Model: "builtin", ConfigHash: "abc", Payload: []byte(`{"id":"ans-1"}`)}
		if err := (AIAnswers{}).Save(ctx, s, in); err != nil {
			t.Fatalf("save answer: %v", err)
		}
		if err := (AIAnswers{}).Save(ctx, s, in); err != nil { // duplicate = no-op
			t.Fatalf("idempotent save: %v", err)
		}
		var n int
		if err := s.Q.QueryRow(ctx, `SELECT count(*) FROM ai_answers WHERE answer_id = 'ans-1'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("answer rows = %d (%v), want 1", n, err)
		}
		// Nothing is old enough to prune; then everything is.
		if pruned, err := (AIAnswers{}).PruneOlderThan(ctx, s, 24*time.Hour); err != nil || pruned != 0 {
			t.Fatalf("prune (young): %v / %d", err, pruned)
		}
		if pruned, err := (AIAnswers{}).PruneOlderThan(ctx, s, 0); err != nil || pruned != 1 {
			t.Fatalf("prune (all): %v / %d", err, pruned)
		}
		return nil
	})
}

func TestTokenStores(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("tok-%d", time.Now().UnixNano()), "Tokens")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// MCP tokens (hash in, tenant/user out; revocation kills auth). user_id
	// has an FK to users, so create a real user inside the tenant scope.
	var userID string
	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		u, err := (Users{}).Create(ctx, s, "mcp-user@example.com", "MCP User")
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		userID = u.ID
		return nil
	})
	mcp := NewMCPTokens(pool)
	// mcp_tokens.token_hash is GLOBAL-unique (auth lookup is pre-tenant), so a fixed
	// fixture secret collides with a leftover row in the reused CI DB even though the
	// tenant is unique — make the secret (hence the hash) unique per run.
	h1 := crypto.Hash([]byte(fmt.Sprintf("mcp-secret-%d", time.Now().UnixNano())))
	if _, err := mcp.Create(ctx, tn.ID, userID, "cli", h1); err != nil {
		t.Fatalf("mcp create: %v", err)
	}
	gotTenant, gotUser, err := mcp.Authenticate(ctx, h1)
	if err != nil || gotTenant != tn.ID || gotUser != userID {
		t.Fatalf("mcp auth: %v / %s / %s", err, gotTenant, gotUser)
	}
	if err := mcp.RevokeForUser(ctx, tn.ID, userID); err != nil {
		t.Fatalf("mcp revoke: %v", err)
	}
	if _, _, err := mcp.Authenticate(ctx, h1); err == nil {
		t.Fatal("revoked MCP token still authenticates")
	}

	// SCIM tokens (create/auth/list/revoke).
	scim := NewScimTokens(pool)
	h2 := crypto.Hash([]byte(fmt.Sprintf("scim-secret-%d", time.Now().UnixNano()))) // global-unique hash → unique per run
	id, err := scim.Create(ctx, tn.ID, "okta", h2)
	if err != nil {
		t.Fatalf("scim create: %v", err)
	}
	if gotTenant, err := scim.Authenticate(ctx, h2); err != nil || gotTenant != tn.ID {
		t.Fatalf("scim auth: %v / %s", err, gotTenant)
	}
	if list, err := scim.List(ctx, tn.ID); err != nil || len(list) != 1 {
		t.Fatalf("scim list: %v / %d", err, len(list))
	}
	if err := scim.Revoke(ctx, tn.ID, id); err != nil {
		t.Fatalf("scim revoke: %v", err)
	}
	if _, err := scim.Authenticate(ctx, h2); err == nil {
		t.Fatal("revoked SCIM token still authenticates")
	}
}

func TestOTLPTokensStrictRLSAndPreTenantAuth(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	sfx := time.Now().UnixNano()
	tnA, err := NewTenants(pool).Create(ctx, fmt.Sprintf("otlp-rls-a-%d", sfx), "OTLP RLS A")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tnB, err := NewTenants(pool).Create(ctx, fmt.Sprintf("otlp-rls-b-%d", sfx), "OTLP RLS B")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}

	otlp := NewOTLPTokens(pool)
	hashA := crypto.Hash([]byte(fmt.Sprintf("otlp-secret-a-%d", sfx)))
	hashB := crypto.Hash([]byte(fmt.Sprintf("otlp-secret-b-%d", sfx)))
	idA, err := otlp.Create(ctx, tnA.ID, "tenant-a", hashA)
	if err != nil {
		t.Fatalf("create tenant A token: %v", err)
	}
	idB, err := otlp.Create(ctx, tnB.ID, "tenant-b", hashB)
	if err != nil {
		t.Fatalf("create tenant B token: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin no-guc tx: %v", err)
	}
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+tenancy.AppRole); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("assume app role: %v", err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM otlp_tokens`).Scan(&count); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("count without tenant GUC: %v", err)
	}
	if count != 0 {
		_ = tx.Rollback(ctx)
		t.Fatalf("direct app-role SELECT without tenant GUC saw %d rows, want 0", count)
	}
	tag, err := tx.Exec(ctx, `UPDATE otlp_tokens SET revoked_at = now() WHERE id = $1`, idA)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("direct app-role UPDATE without tenant GUC: %v", err)
	}
	if tag.RowsAffected() != 0 {
		_ = tx.Rollback(ctx)
		t.Fatalf("direct app-role UPDATE without tenant GUC touched %d rows, want 0", tag.RowsAffected())
	}
	var authTenant string
	if err := tx.QueryRow(ctx, `SELECT tenant_id::text FROM otlp_authenticate_token($1)`, hashA).Scan(&authTenant); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("pre-tenant auth function: %v", err)
	}
	if authTenant != tnA.ID {
		_ = tx.Rollback(ctx)
		t.Fatalf("pre-tenant auth tenant = %s, want %s", authTenant, tnA.ID)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback no-guc tx: %v", err)
	}

	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tenant-guc tx: %v", err)
	}
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+tenancy.AppRole); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("assume app role for tenant GUC: %v", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('probectl.tenant_id', $1, true)", tnA.ID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("set tenant GUC: %v", err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM otlp_tokens`).Scan(&count); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("count with tenant GUC: %v", err)
	}
	if count != 1 {
		_ = tx.Rollback(ctx)
		t.Fatalf("direct app-role SELECT with tenant A GUC saw %d rows, want 1", count)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback tenant-guc tx: %v", err)
	}

	gotTenant, err := otlp.Authenticate(ctx, hashA)
	if err != nil || gotTenant != tnA.ID {
		t.Fatalf("store auth tenant A: %v / %s", err, gotTenant)
	}
	listA, err := otlp.List(ctx, tnA.ID)
	if err != nil {
		t.Fatalf("list tenant A: %v", err)
	}
	if len(listA) != 1 || listA[0].ID != idA || listA[0].TenantID != tnA.ID {
		t.Fatalf("tenant A list = %+v, want only %s", listA, idA)
	}
	listB, err := otlp.List(ctx, tnB.ID)
	if err != nil {
		t.Fatalf("list tenant B: %v", err)
	}
	if len(listB) != 1 || listB[0].ID != idB || listB[0].TenantID != tnB.ID {
		t.Fatalf("tenant B list = %+v, want only %s", listB, idB)
	}
	if err := otlp.Revoke(ctx, tnA.ID, idB); err != ErrInvalidOTLPToken {
		t.Fatalf("tenant A revoke of tenant B token = %v, want ErrInvalidOTLPToken", err)
	}
}

func TestSIEMCursorAndIntegrationLinks(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("sie-%d", time.Now().UnixNano()), "SIEM")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		// SIEM delivery cursor: starts at zero, advances monotonically.
		if cur, err := (SIEMDelivery{}).Cursor(ctx, s); err != nil || cur != 0 {
			t.Fatalf("initial cursor: %v / %d", err, cur)
		}
		if err := (SIEMDelivery{}).Advance(ctx, s, 42); err != nil {
			t.Fatalf("advance: %v", err)
		}
		if cur, err := (SIEMDelivery{}).Cursor(ctx, s); err != nil || cur != 42 {
			t.Fatalf("cursor after advance: %v / %d", err, cur)
		}

		// Incident integration links need a real incident (FK).
		now := time.Now().UTC()
		inc, err := (Incidents{}).Create(ctx, s, incident.Incident{
			TenantID: tn.ID, Status: incident.StatusOpen, Severity: incident.SeverityCritical,
			Title: "linked incident", StartedAt: now, LastSeenAt: now,
		})
		if err != nil {
			t.Fatalf("create incident: %v", err)
		}
		l := notify.Link{TenantID: tn.ID, IncidentID: inc.ID, Connector: "pagerduty", ExternalRef: "PD-1", Status: "open"}
		if err := (IncidentIntegrations{}).Upsert(ctx, s, l); err != nil {
			t.Fatalf("upsert link: %v", err)
		}
		l.Status = "resolved"
		if err := (IncidentIntegrations{}).Upsert(ctx, s, l); err != nil {
			t.Fatalf("upsert (update) link: %v", err)
		}
		if got, err := (IncidentIntegrations{}).Get(ctx, s, inc.ID, "pagerduty"); err != nil || got == nil || got.Status != "resolved" {
			t.Fatalf("get link: %v / %+v", err, got)
		}
		if got, err := (IncidentIntegrations{}).FindByRef(ctx, s, "pagerduty", "PD-1"); err != nil || got == nil || got.IncidentID != inc.ID {
			t.Fatalf("find by ref: %v / %+v", err, got)
		}
		if list, err := (IncidentIntegrations{}).ListForIncident(ctx, s, inc.ID); err != nil || len(list) != 1 {
			t.Fatalf("list links: %v / %d", err, len(list))
		}
		return nil
	})
}
