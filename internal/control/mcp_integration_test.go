//go:build integration

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/pathstore"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func mcpCall(t *testing.T, srv interface {
	Handle(context.Context, *auth.Principal, []byte) []byte
}, p *auth.Principal, id int, method string, params any) map[string]any {
	t.Helper()
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	raw, _ := json.Marshal(req)
	var resp map[string]any
	if err := json.Unmarshal(srv.Handle(context.Background(), p, raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return resp
}

func mcpToolResult(t *testing.T, srv interface {
	Handle(context.Context, *auth.Principal, []byte) []byte
}, p *auth.Principal, id int, name string, args any) map[string]any {
	t.Helper()
	params := map[string]any{"name": name}
	if args != nil {
		params["arguments"] = args
	}
	resp := mcpCall(t, srv, p, id, "tools/call", params)
	res, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("%s: expected a tool result, got %v", name, resp)
	}
	return res
}

// End-to-end MCP against Postgres (S25 Done-when): an MCP client queries probectl
// strictly within the caller's RBAC scope; a tenant cannot see another tenant's
// incident; and a control-plane token resolves to its tenant + user.
func TestMCPServerToolsTenantScopedAndTokenAuth(t *testing.T) {
	_, db := setupAPI(t)
	c := BuildCorrelator(db.Pool(), 5*time.Minute, quietLog())
	ctx := context.Background()
	// A fresh tenant isolates this test from the shared integration DB (the default
	// tenant's incidents are asserted on by TestIncidentCorrelationAndAPI).
	tnA, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("mcpmain-%d", time.Now().UnixNano()), "MCP Main")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tenant := tnA.ID
	now := time.Now().UTC().Truncate(time.Second)

	inc, err := c.Ingest(ctx, incident.Signal{
		TenantID: tenant, Plane: "bgp", Kind: "bgp.possible_hijack", Severity: incident.SeverityCritical,
		Title: "possible hijack 192.0.2.0/24", Target: "192.0.2.0/24", Prefix: "192.0.2.0/24", OccurredAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{AIMaxEvidence: 50}
	srv := NewMCPServer(cfg, quietLog(), db.Pool(), pathstore.NewMemory(), 120)
	// A fully-capable analyst: the direct-read perms (test/incident/events) PLUS the
	// unified-query perms the AI engine enforces (entities/metrics/topology + ai.query),
	// matching the grant set seeded for AI-capable roles in migration 0015. Without
	// entities.read the engine's entities domain is forbidden and the RCA finds no
	// evidence.
	full := &auth.Principal{TenantID: tenant, Permissions: map[string]bool{
		"test.read": true, "incident.read": true, "events.read": true, "ai.query": true,
		"entities.read": true, "metrics.read": true, "topology.read": true,
	}}

	// tools/list shows the full read catalog to an all-perms caller.
	tools, _ := mcpCall(t, srv, full, 1, "tools/list", nil)["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 7 {
		t.Errorf("tools/list = %d tools, want 7", len(tools))
	}

	// get_incident returns the seeded incident.
	res := mcpToolResult(t, srv, full, 2, "get_incident", map[string]any{"id": inc.ID})
	if res["isError"] == true {
		t.Fatalf("get_incident errored: %v", res)
	}
	if sc, _ := res["structuredContent"].(map[string]any); sc["id"] != inc.ID {
		t.Errorf("get_incident structuredContent id = %v, want %s", sc["id"], inc.ID)
	}

	// explain_degradation returns a cited RCA grounded in the incident.
	res = mcpToolResult(t, srv, full, 3, "explain_degradation",
		map[string]any{"question": "why is 192.0.2.0/24 unreachable? any routing changes?"})
	if res["isError"] == true {
		t.Fatalf("explain_degradation errored: %v", res)
	}
	sc, _ := res["structuredContent"].(map[string]any)
	if rc, _ := sc["root_cause"].(string); !strings.Contains(strings.ToLower(rc), "hijack") {
		t.Errorf("explain_degradation root cause = %q, want it to name the routing signal", rc)
	}

	// list_tests works (empty in a fresh tenant).
	if mcpToolResult(t, srv, full, 4, "list_tests", nil)["isError"] == true {
		t.Error("list_tests should not error")
	}

	// A test.read-only caller cannot list or call incident tools.
	limited := &auth.Principal{TenantID: tenant, Permissions: map[string]bool{"test.read": true}}
	if code, _ := mcpCall(t, srv, limited, 5, "tools/call",
		map[string]any{"name": "get_incident", "arguments": map[string]any{"id": inc.ID}})["error"].(map[string]any)["code"].(float64); int(code) != -32002 {
		t.Errorf("limited caller calling get_incident: code = %v, want -32002 (forbidden)", code)
	}

	// Tenant isolation: another tenant cannot see tenant A's incident.
	tn, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("mcpiso-%d", time.Now().UnixNano()), "MCP Isolation")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	other := &auth.Principal{TenantID: tn.ID, Permissions: map[string]bool{"incident.read": true}}
	if res := mcpToolResult(t, srv, other, 6, "get_incident", map[string]any{"id": inc.ID}); res["isError"] != true {
		t.Errorf("another tenant must not read tenant A's incident, got %v", res)
	}

	// Token auth: a control-plane token resolves to its tenant + user.
	var userID string
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, scp tenancy.Scope) error {
		u, e := store.Users{}.Create(ctx, scp, fmt.Sprintf("mcp-%d@example.com", time.Now().UnixNano()), "MCP User")
		if e != nil {
			return e
		}
		userID = u.ID
		return nil
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	token, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewMCPTokens(db.Pool()).Create(ctx, tenant, userID, "test", crypto.Hash([]byte(token))); err != nil {
		t.Fatalf("create token: %v", err)
	}
	princ, err := NewMCPAuthenticator(db.Pool()).Authenticate(ctx, token)
	if err != nil {
		t.Fatalf("authenticate token: %v", err)
	}
	if princ.TenantID != tenant || princ.UserID != userID {
		t.Errorf("token resolved to tenant=%s user=%s, want %s/%s", princ.TenantID, princ.UserID, tenant, userID)
	}
	if _, err := NewMCPAuthenticator(db.Pool()).Authenticate(ctx, "bogus-token"); err == nil {
		t.Error("an invalid token must fail authentication")
	}
}
