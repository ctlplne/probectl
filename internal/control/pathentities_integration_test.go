// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The two routes share a real FORCE-RLS database. A foreign context cannot be
// bound even if a caller guesses its UUID, and a missing binding never makes
// an RFC1918 hop global across two tenants.
func TestPathEntityRoutesRequireOperatorContextAndTenant(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	h := srv.Handler()
	a, b := freshTenant(t, db, "path-entity-a"), freshTenant(t, db, "path-entity-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove path entity fixture tenants: %v", err)
		}
	})
	contexts := make(map[string]string)
	tests := make(map[string]string)
	saveTrace := func(tenant string, p *path.Path) error {
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
		var startedAt time.Time
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&startedAt)
		}); err != nil {
			return err
		}
		return srv.pathStore.Save(pathstore.WithDiscoveryStartedAt(ctx, startedAt), tenant, p)
	}
	for _, tenant := range []string{a, b} {
		contexts[tenant] = uuid(t)
		tests[tenant] = uuid(t)
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tests (tenant_id,id,name,target)
				VALUES ($1,$2,$3,'10.42.0.1')`, tenant, tests[tenant], "entity-path-"+tenant); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
                VALUES ($1,$2,$3,$4,$3::text,$4::text)`,
				tenant, contexts[tenant], uuid(t), uuid(t))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if tenant != a {
			continue // An unbound test is explicit even before its first trace.
		}
		if err := saveTrace(tenant, &path.Path{
			Target: "10.42.0.1", TargetIP: "10.42.0.1", Mode: "icmp",
			Hops: []path.Hop{{TTL: 1, Nodes: []path.HopNode{
				{IP: "10.42.0.254"}, {IP: "2001:0DB8::1"}, {IP: "invalid-ip"},
			}}},
			Links: []path.Link{},
		}); err != nil {
			t.Fatal(err)
		}
	}
	read := func(tenant string) struct {
		Status    string `json:"status"`
		ContextID string `json:"context_id"`
		Items     []struct {
			IP         string `json:"ip"`
			Resolution struct {
				Status string `json:"status"`
			} `json:"resolution"`
		} `json:"items"`
	} {
		t.Helper()
		rec := apiReq(t, h, http.MethodGet, "/v1/tests/"+tests[tenant]+"/path/entities", tenant, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("path entities tenant=%s: %d %s", tenant, rec.Code, rec.Body.String())
		}
		var result struct {
			Status    string `json:"status"`
			ContextID string `json:"context_id"`
			Items     []struct {
				IP         string `json:"ip"`
				Resolution struct {
					Status string `json:"status"`
				} `json:"resolution"`
			} `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	if got := read(a); got.Status != "unbound" || len(got.Items) != 0 {
		t.Fatalf("unbound path guessed identity: %+v", got)
	}
	if rec := apiReq(t, h, http.MethodPut,
		"/v1/tests/"+tests[a]+"/entity-context", a,
		map[string]string{"context_id": contexts[b]}); rec.Code == http.StatusOK {
		t.Fatalf("foreign tenant context bound to test: %s", rec.Body.String())
	}
	if rec := apiReq(t, h, http.MethodPut,
		"/v1/tests/"+tests[b]+"/entity-context", a,
		map[string]string{"context_id": contexts[a]}); rec.Code == http.StatusOK {
		t.Fatalf("foreign tenant test bound to context: %s", rec.Body.String())
	}
	if rec := apiReq(t, h, http.MethodPut,
		"/v1/tests/"+tests[a]+"/entity-context", a,
		map[string]string{"context_id": contexts[a]}); rec.Code != http.StatusOK {
		t.Fatalf("own test/context assignment: %d %s", rec.Code, rec.Body.String())
	}
	// A legacy/imported round has no PostgreSQL-clock proof, even if its
	// process clock happens to date it after this new binding.
	if err := srv.pathStore.Save(tenancy.WithTenant(context.Background(), tenancy.ID(a)), a,
		&path.Path{Target: "10.42.0.1", Hops: []path.Hop{{TTL: 1,
			Nodes: []path.HopNode{{IP: "10.42.0.253"}}}}}); err != nil {
		t.Fatal(err)
	}
	// A stored round from before the binding has no proven routing context.
	if got := read(a); got.Status != "awaiting_trace" || got.ContextID != contexts[a] || len(got.Items) != 0 {
		t.Fatalf("pre-binding path inherited new routing context: %+v", got)
	}
	mcpServer := NewMCPServerWithPolicyLoader(&config.Config{},
		slog.New(slog.NewTextHandler(io.Discard, nil)), db.Pool(), srv.pathStore, 0,
		ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil },
			func(context.Context, ai.EgressEvent) error { return nil }, ai.RedactionPolicy{}),
		nil, nil, func(context.Context, string) ([]auth.Policy, error) { return nil, nil })
	principalA := &auth.Principal{TenantID: a, UserID: "path-operator",
		Permissions: map[string]bool{"agent.write": true, "entities.read": true, "test.read": true}}
	if data, failed := nativeControlCall(t, mcpServer, principalA, "entity_path_resolve",
		mcp.EntityPathResolveInput{TestID: tests[a]}); failed {
		t.Fatalf("MCP pre-binding path failed: %s", data)
	} else {
		var pending mcp.EntityPathResult
		if err := json.Unmarshal(data, &pending); err != nil || pending.Status != "awaiting_trace" ||
			pending.ContextID != contexts[a] || len(pending.Items) != 0 {
			t.Fatalf("MCP pre-binding path inherited context: %+v, %v", pending, err)
		}
	}
	if err := saveTrace(a, &path.Path{
		Target: "10.42.0.1", TargetIP: "10.42.0.1", Mode: "icmp",
		Hops: []path.Hop{{TTL: 1, Nodes: []path.HopNode{
			{IP: "10.42.0.254"}, {IP: "2001:0DB8::1"}, {IP: "invalid-ip"},
		}}}, Links: []path.Link{},
	}); err != nil {
		t.Fatal(err)
	}
	got := read(a)
	if got.Status != "current" || got.ContextID != contexts[a] || len(got.Items) != 3 ||
		got.Items[0].IP != "10.42.0.254" || got.Items[0].Resolution.Status != "unresolved" ||
		got.Items[1].IP != "2001:0DB8::1" || got.Items[1].Resolution.Status != "unresolved" ||
		got.Items[2].IP != "invalid-ip" || got.Items[2].Resolution.Status != "unresolved" {
		t.Fatalf("own path current identity: %+v", got)
	}
	if got := read(b); got.Status != "unbound" || len(got.Items) != 0 {
		t.Fatalf("other tenant path inherited binding: %+v", got)
	}
	for _, fixture := range []struct{ tenant, ownTest, ownContext, foreignTest, foreignContext string }{
		{a, tests[a], contexts[a], tests[b], contexts[b]},
		{b, tests[b], contexts[b], tests[a], contexts[a]},
	} {
		principal := &auth.Principal{TenantID: fixture.tenant, UserID: "path-operator",
			Permissions: map[string]bool{"agent.write": true, "entities.read": true, "test.read": true}}
		if _, failed := nativeControlCall(t, mcpServer, principal, "entity_path_context_assign",
			mcp.EntityPathContextInput{TestID: fixture.foreignTest, ContextID: fixture.ownContext}); !failed {
			t.Fatalf("MCP tenant %s bound foreign test", fixture.tenant)
		}
		if _, failed := nativeControlCall(t, mcpServer, principal, "entity_path_context_assign",
			mcp.EntityPathContextInput{TestID: fixture.ownTest, ContextID: fixture.foreignContext}); !failed {
			t.Fatalf("MCP tenant %s bound foreign context", fixture.tenant)
		}
		if _, failed := nativeControlCall(t, mcpServer, principal, "entity_path_resolve",
			mcp.EntityPathResolveInput{TestID: fixture.foreignTest}); !failed {
			t.Fatalf("MCP tenant %s resolved foreign test", fixture.tenant)
		}
		data, failed := nativeControlCall(t, mcpServer, principal, "entity_path_resolve",
			mcp.EntityPathResolveInput{TestID: fixture.ownTest})
		var result mcp.EntityPathResult
		if failed || json.Unmarshal(data, &result) != nil {
			t.Fatalf("MCP path identity tenant=%s: %s", fixture.tenant, data)
		}
		if fixture.tenant == a {
			if result.Status != "current" || result.ContextID != fixture.ownContext ||
				len(result.Items) != 3 || result.Items[0].Resolution.Status != "unresolved" {
				t.Fatalf("MCP own path identity: %+v", result)
			}
		} else if result.Status != "unbound" || len(result.Items) != 0 {
			t.Fatalf("MCP other tenant inherited path identity: %+v", result)
		}
	}
	secondTest := uuid(t)
	ctxA := tenancy.WithTenant(context.Background(), tenancy.ID(a))
	if err := tenancy.InTenant(ctxA, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO tests (tenant_id,id,name,target)
			VALUES ($1,$2,'second-path','https://10.42.0.1:443/health')`, a, secondTest)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	secondContext := apiReq(t, h, http.MethodPost, "/v1/entity-contexts", a,
		map[string]string{"site_label": "West DC", "vrf_label": "Customer B"})
	if secondContext.Code != http.StatusCreated {
		t.Fatalf("second path context: %d %s", secondContext.Code, secondContext.Body.String())
	}
	var next struct {
		ContextID string `json:"context_id"`
	}
	if err := json.Unmarshal(secondContext.Body.Bytes(), &next); err != nil {
		t.Fatal(err)
	}
	if rec := apiReq(t, h, http.MethodPut,
		"/v1/tests/"+secondTest+"/entity-context", a,
		map[string]string{"context_id": next.ContextID}); rec.Code != http.StatusConflict {
		t.Fatalf("second VRF claimed the same path destination: %d %s", rec.Code, rec.Body.String())
	}
	if rec := apiReq(t, h, http.MethodPut,
		"/v1/tests/"+tests[a]+"/entity-context", a,
		map[string]string{"context_id": next.ContextID}); rec.Code != http.StatusOK {
		t.Fatalf("rebind path to second VRF: %d %s", rec.Code, rec.Body.String())
	}
	if got := read(a); got.Status != "awaiting_trace" || got.ContextID != next.ContextID || len(got.Items) != 0 {
		t.Fatalf("pre-rebind path inherited second VRF: %+v", got)
	}
	if data, failed := nativeControlCall(t, mcpServer, principalA, "entity_path_resolve",
		mcp.EntityPathResolveInput{TestID: tests[a]}); failed {
		t.Fatalf("MCP pre-rebind path failed: %s", data)
	} else {
		var pending mcp.EntityPathResult
		if err := json.Unmarshal(data, &pending); err != nil || pending.Status != "awaiting_trace" ||
			pending.ContextID != next.ContextID || len(pending.Items) != 0 {
			t.Fatalf("MCP pre-rebind path inherited context: %+v, %v", pending, err)
		}
	}
	if err := saveTrace(a, &path.Path{
		Target: "10.42.0.1", TargetIP: "10.42.0.1", Mode: "icmp",
		Hops:  []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: "10.42.0.254"}}}},
		Links: []path.Link{},
	}); err != nil {
		t.Fatal(err)
	}
	if got := read(a); got.Status != "current" || got.ContextID != next.ContextID || len(got.Items) != 1 {
		t.Fatalf("fresh second-VRF trace did not resolve in new context: %+v", got)
	}
	if err := tenancy.InTenant(ctxA, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE tests SET target='10.42.0.2'
			WHERE tenant_id=$1 AND id=$2`, a, tests[a])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := read(a); got.Status != "unbound" || len(got.Items) != 0 {
		t.Fatalf("retargeted test inherited stale path context: %+v", got)
	}
}
