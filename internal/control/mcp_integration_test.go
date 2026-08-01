// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
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
	// The MCP caller is an external-AI client, so every tool call is egress-gated
	// on the tenant's ai_remote_egress consent (AIRCA-001/005, default-deny). This
	// test exercises tool RBAC + tenant scoping, not the egress gate, so grant the
	// consent for this tenant — via the provider scope, the path production uses.
	if err := tenancy.InProvider(ctx, db.Pool(), func(ctx context.Context, q tenancy.Querier) error {
		_, e := q.Exec(ctx,
			`INSERT INTO tenant_governance (tenant_id, ai_remote_egress) VALUES ($1, true)
			 ON CONFLICT (tenant_id) DO UPDATE SET ai_remote_egress = true`, tenant)
		return e
	}); err != nil {
		t.Fatalf("grant ai_remote_egress consent: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)

	inc, err := c.Ingest(ctx, incident.Signal{
		TenantID: tenant, Plane: "bgp", Kind: "bgp.possible_hijack", Severity: incident.SeverityCritical,
		Title: "possible hijack 192.0.2.0/24", Target: "192.0.2.0/24", Prefix: "192.0.2.0/24", OccurredAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{AIMaxEvidence: 50}
	log := quietLog()
	srv := NewMCPServer(cfg, log, db.Pool(), pathstore.NewMemory(), 120, NewAIEgressGate(cfg, log, db.Pool()), nil, nil)
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

func TestMCPABACDenyOverridesRBACTwoTenant(t *testing.T) {
	_, db := setupAPIServerWithLatest(t, nil)
	ctx := context.Background()
	stamp := time.Now().UnixNano()
	tenantA, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("mcp-abac-a-%d", stamp), "MCP ABAC A")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tenantB, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("mcp-abac-b-%d", stamp), "MCP ABAC B")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}
	log := quietLog()
	egress := ai.NewEgressGate(func(context.Context, string) (bool, error) {
		return true, nil
	}, func(context.Context, ai.EgressEvent) error {
		return nil
	}, ai.RedactionPolicy{})
	srv := NewMCPServer(
		&config.Config{AIMaxEvidence: 10},
		log,
		db.Pool(),
		pathstore.NewMemory(),
		120,
		egress,
		nil,
		nil,
	)
	authenticate := func(t *testing.T, tenantID, userID string) *auth.Principal {
		t.Helper()
		token, err := auth.RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.NewMCPTokens(db.Pool()).Create(ctx, tenantID, userID, "abac", crypto.Hash([]byte(token))); err != nil {
			t.Fatalf("create MCP token: %v", err)
		}
		principal, err := NewMCPAuthenticator(db.Pool()).Authenticate(ctx, token)
		if err != nil {
			t.Fatalf("authenticate MCP token: %v", err)
		}
		return principal
	}
	userA := createUserWithPerm(t, db, tenantA.ID, fmt.Sprintf("mcp-a-%d@example.com", stamp),
		map[string]string{"department": "contractor"}, "test.read")
	userB := createUserWithPerm(t, db, tenantB.ID, fmt.Sprintf("mcp-b-%d@example.com", stamp),
		map[string]string{"department": "contractor"}, "test.read")
	tenantAPrincipal := authenticate(t, tenantA.ID, userA)
	tenantBPrincipal := authenticate(t, tenantB.ID, userB)

	toolNames := func(t *testing.T, principal *auth.Principal, id int) map[string]bool {
		t.Helper()
		result, ok := mcpCall(t, srv, principal, id, "tools/list", nil)["result"].(map[string]any)
		if !ok {
			t.Fatalf("tools/list returned no result")
		}
		tools, _ := result["tools"].([]any)
		names := make(map[string]bool, len(tools))
		for _, raw := range tools {
			tool, _ := raw.(map[string]any)
			name, _ := tool["name"].(string)
			names[name] = true
		}
		return names
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantA.ID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{
			Name:       "deny-contractor-test-read",
			Effect:     auth.PolicyDeny,
			Permission: "test.read",
			Subject:    map[string]string{"department": "contractor"},
			Enabled:    true,
		})
		return err
	}); err != nil {
		t.Fatalf("create tenant A policy: %v", err)
	}

	if names := toolNames(t, tenantAPrincipal, 19); names["list_tests"] || names["get_path"] {
		t.Fatalf("tenant A discovered ABAC-denied tools: %v", names)
	}
	if names := toolNames(t, tenantBPrincipal, 20); !names["list_tests"] || !names["get_path"] {
		t.Fatalf("tenant B inherited tenant A's deny policy: %v", names)
	}

	denied := mcpCall(t, srv, tenantAPrincipal, 21, "tools/call", map[string]any{"name": "list_tests"})
	rpcErr, _ := denied["error"].(map[string]any)
	if code, _ := rpcErr["code"].(float64); int(code) != -32002 {
		t.Fatalf("tenant A ABAC-denied call code = %v, want -32002", rpcErr["code"])
	}
	if result := mcpToolResult(t, srv, tenantBPrincipal, 22, "list_tests", nil); result["isError"] == true {
		t.Fatalf("tenant B's policy-isolated call failed: %v", result)
	}
}

func TestMCPListTestsBoundedAndTenantScoped(t *testing.T) {
	_, db := setupAPI(t)
	ctx := context.Background()
	tenants := store.NewTenants(db.Pool())
	tenantA, err := tenants.Create(ctx, fmt.Sprintf("mcplimita-%d", time.Now().UnixNano()), "MCP Limit A")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tenantB, err := tenants.Create(ctx, fmt.Sprintf("mcplimitb-%d", time.Now().UnixNano()), "MCP Limit B")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}

	seedTests := func(tenantID string, count int) {
		t.Helper()
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			for i := 0; i < count; i++ {
				if _, err := (store.Tests{}).Create(ctx, sc, store.TestInput{
					Name:            fmt.Sprintf("bounded-%03d", i),
					Type:            "tcp",
					Target:          fmt.Sprintf("192.0.2.%d:443", i%250+1),
					IntervalSeconds: 60,
					TimeoutSeconds:  5,
					Enabled:         true,
				}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("seed %s tests: %v", tenantID, err)
		}
	}
	seedTests(tenantA.ID, mcpMaxListedTests+1)
	seedTests(tenantB.ID, mcpMaxListedTests)

	allowEgress := ai.NewEgressGate(
		func(context.Context, string) (bool, error) { return true, nil },
		func(context.Context, ai.EgressEvent) error { return nil },
		ai.RedactionPolicy{},
	)
	srv := NewMCPServer(
		&config.Config{},
		quietLog(),
		db.Pool(),
		pathstore.NewMemory(),
		120,
		allowEgress,
		nil,
		nil,
	)
	call := func(id int, tenantID string) map[string]any {
		t.Helper()
		p := &auth.Principal{TenantID: tenantID, Permissions: map[string]bool{"test.read": true}}
		result := mcpToolResult(t, srv, p, id, "list_tests", nil)
		if result["isError"] == true {
			t.Fatalf("tenant %s list_tests returned an error: %v", tenantID, result)
		}
		structured, ok := result["structuredContent"].(map[string]any)
		if !ok {
			t.Fatalf("tenant %s structuredContent = %T, want object", tenantID, result["structuredContent"])
		}
		return structured
	}

	assertTenantRows := func(structured map[string]any, tenantID string, want int, truncated bool) {
		t.Helper()
		rows, ok := structured["tests"].([]any)
		if !ok {
			t.Fatalf("tenant %s tests = %T, want array", tenantID, structured["tests"])
		}
		if len(rows) != want {
			t.Fatalf("tenant %s tests = %d, want %d", tenantID, len(rows), want)
		}
		if got, _ := structured["truncated"].(bool); got != truncated {
			t.Fatalf("tenant %s truncated = %v, want %v", tenantID, got, truncated)
		}
		if got, _ := structured["limit"].(float64); int(got) != mcpMaxListedTests {
			t.Fatalf("tenant %s limit = %v, want %d", tenantID, structured["limit"], mcpMaxListedTests)
		}
		for _, row := range rows {
			testRow, ok := row.(map[string]any)
			if !ok {
				t.Fatalf("tenant %s test row = %T, want object", tenantID, row)
			}
			if got := testRow["tenant_id"]; got != tenantID {
				t.Fatalf("tenant %s received row scoped to %v", tenantID, got)
			}
		}
	}

	assertTenantRows(call(1, tenantA.ID), tenantA.ID, mcpMaxListedTests, true)
	assertTenantRows(call(2, tenantB.ID), tenantB.ID, mcpMaxListedTests, false)
}

func TestMCPAuthenticatorLoadsTenantAttributes(t *testing.T) {
	_, db := setupAPI(t)
	ctx := context.Background()
	stamp := time.Now().UnixNano()
	tenantA, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("mcp-auth-attrs-a-%d", stamp), "MCP Attr A")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tenantB, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("mcp-auth-attrs-b-%d", stamp), "MCP Attr B")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}

	createPrincipal := func(t *testing.T, tenantID, department string) *auth.Principal {
		t.Helper()
		var userID string
		email := fmt.Sprintf("mcp-attrs-%s-%d@example.com", department, stamp)
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (store.Users{}).CreateSCIM(ctx, sc, store.User{
				Email: email, UserName: email, DisplayName: "MCP Attr User",
				Attributes: map[string]string{"department": department},
			})
			if err == nil {
				userID = user.ID
			}
			return err
		}); err != nil {
			t.Fatalf("create %s user: %v", department, err)
		}
		token, err := auth.RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.NewMCPTokens(db.Pool()).Create(ctx, tenantID, userID, "attrs", crypto.Hash([]byte(token))); err != nil {
			t.Fatalf("create %s token: %v", department, err)
		}
		principal, err := NewMCPAuthenticator(db.Pool()).Authenticate(ctx, token)
		if err != nil {
			t.Fatalf("authenticate %s token: %v", department, err)
		}
		return principal
	}

	principalA := createPrincipal(t, tenantA.ID, "contractor")
	principalB := createPrincipal(t, tenantB.ID, "sre")
	if principalA.TenantID != tenantA.ID ||
		principalA.Attributes["department"] != "contractor" ||
		principalA.Attributes["mfa"] != "false" {
		t.Fatalf("tenant A principal attributes = tenant %q attrs %v", principalA.TenantID, principalA.Attributes)
	}
	if principalB.TenantID != tenantB.ID ||
		principalB.Attributes["department"] != "sre" ||
		principalB.Attributes["mfa"] != "false" {
		t.Fatalf("tenant B principal attributes = tenant %q attrs %v", principalB.TenantID, principalB.Attributes)
	}
	if principalA.Attributes["department"] == principalB.Attributes["department"] {
		t.Fatalf("MCP subject attributes crossed tenants: A=%v B=%v", principalA.Attributes, principalB.Attributes)
	}
}
