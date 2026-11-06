// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual modern/legacy native HTTP, verified TLS, bearer authentication and
// current Postgres permissions/configuration. Sender identities are seeded;
// this root does not claim real SNMP/BMP or stdio process proof.
func TestInterfaceRoleNativeTLSKeepsTenantConfigurationAndCurrentSources(t *testing.T) {
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(wire, func(t *testing.T) { proveInterfaceRoleNativeTLS(t, wire) })
	}
}

func proveInterfaceRoleNativeTLS(t *testing.T, wire string) {
	t.Helper()
	f := newRoleExplanationAPIFixture(t)
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO tenant_governance (tenant_id,ai_remote_egress) VALUES($1,true) ON CONFLICT(tenant_id) DO UPDATE SET ai_remote_egress=true`, tenant)
			return err
		})
	}
	cfg := &config.Config{}
	server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, pathstore.NewMemory(), 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
	socket := httptest.NewTLSServer(server.HTTPHandler(NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)))
	t.Cleanup(socket.Close)
	if wire == "2025-11-25" {
		for _, tenant := range f.tenants {
			proveLegacyMCPInitializationTLS(t, socket, f.tokens[tenant])
		}
	}
	call := func(tenant, tool string, args any, target any, wantOK bool) {
		t.Helper()
		params := map[string]any{"name": tool, "arguments": args}
		if wire == "2026-07-28" {
			params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": wire, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
		}
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range map[string]string{"Authorization": "Bearer " + f.tokens[tenant], "Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": wire, "Mcp-Method": "tools/call", "Mcp-Name": tool, "X-Probectl-Tenant": f.tenants[1]} {
			req.Header.Set(key, value)
		}
		response, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 128<<20+1))
		if err != nil || len(raw) > 128<<20 {
			t.Fatal("native role response lost whole-result admission", err)
		}
		if response.Header.Get("Content-Type") == "text/event-stream" {
			var final []byte
			for _, line := range bytes.Split(raw, []byte{'\n'}) {
				if bytes.HasPrefix(line, []byte("data: ")) {
					final = bytes.TrimPrefix(line, []byte("data: "))
				}
			}
			raw = final
		}
		var reply struct {
			Error  json.RawMessage `json:"error"`
			Result struct {
				IsError    bool                       `json:"isError"`
				ResultType string                     `json:"resultType"`
				Meta       map[string]json.RawMessage `json:"_meta"`
				Data       json.RawMessage            `json:"structuredContent"`
				Content    []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if json.Unmarshal(raw, &reply) != nil {
			t.Fatal("native role response is not a complete RPC frame", response.StatusCode)
		}
		ok := response.StatusCode == http.StatusOK && len(reply.Error) == 0 && !reply.Result.IsError && len(reply.Result.Data) > 0 && string(reply.Result.Data) != "null"
		if ok != wantOK {
			t.Fatalf("native role %s success=%v expected=%v: %.600s", tool, ok, wantOK, raw)
		}
		if !ok {
			if len(reply.Result.Data) > 0 && string(reply.Result.Data) != "null" {
				t.Fatal("refused native role call disclosed structured data")
			}
			return
		}
		if wire == "2026-07-28" && (reply.Result.ResultType != "complete" || len(reply.Result.Meta["io.modelcontextprotocol/serverInfo"]) == 0) {
			t.Fatal("modern role RPC lost complete metadata")
		}
		if wire == "2025-11-25" && (reply.Result.ResultType != "" || len(reply.Result.Meta) != 0) {
			t.Fatal("legacy role RPC inherited modern metadata")
		}
		if len(reply.Result.Content) != 1 || !bytes.Equal(bytes.TrimSpace([]byte(reply.Result.Content[0].Text)), bytes.TrimSpace(reply.Result.Data)) {
			t.Fatal("native role text and structured results disagree")
		}
		if target != nil && json.Unmarshal(reply.Result.Data, target) != nil {
			t.Fatal("native role result lost its typed complete representation")
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	readArgs := map[string]any{"context_id": f.contextID, "interface_id": f.interfaceID}
	explain := func(tenant string, want entity.InterfaceRole) {
		t.Helper()
		var out interfaceRoleExplanation
		call(tenant, "interface_role_explain", readArgs, &out, true)
		if out.TenantID != tenant || out.ContextID != f.contextID || out.InterfaceID != f.interfaceID || out.Role != want || len(out.Sources) == 0 {
			t.Fatal("native role response lost current tenant/source identity", out)
		}
	}
	explain(a, entity.InterfaceRoleTransit)
	explain(b, entity.InterfaceRoleTransit)
	var policy entity.InterfaceRolePolicyRecord
	call(a, "interface_role_policy", map[string]any{"context_id": f.contextID}, &policy, true)
	if policy.TenantID != a || len(policy.Definition.ProviderASNs) != 1 || policy.Definition.ProviderASNs[0] != 64496 {
		t.Fatal("native policy used the untrusted tenant hint", policy)
	}
	var saved entity.InterfaceRoleOverrideRecord
	call(a, "interface_role_override_set", map[string]any{"context_id": f.contextID, "interface_id": f.interfaceID, "expected_id": "", "expected_revision": "0", "role": "private_peering"}, &saved, true)
	if saved.TenantID != a || saved.ID == "" || saved.Revision != "1" || saved.Role != entity.InterfaceRolePrivate {
		t.Fatal("native override lost tenant incarnation", saved)
	}
	var retained entity.InterfaceRoleOverrideRecord
	call(a, "interface_role_override", readArgs, &retained, true)
	if retained.ID != saved.ID || retained.Revision != saved.Revision {
		t.Fatal("native override read lost exact incarnation", retained)
	}
	explain(a, entity.InterfaceRolePrivate)
	explain(b, entity.InterfaceRoleTransit)
	call(a, "interface_role_override_reset", map[string]any{"context_id": f.contextID, "interface_id": f.interfaceID, "expected_id": saved.ID, "expected_revision": saved.Revision, "confirmed": true}, nil, true)
	explain(a, entity.InterfaceRoleTransit)
	// The complete saved policy remains complete through actual RPC framing and
	// bounded redaction, rather than only a mocked native backend.
	saveCompleteRoleExplanationPolicy(f, a)
	call(a, "interface_role_policy", map[string]any{"context_id": f.contextID}, &policy, true)
	if len(policy.Definition.DescriptionRules) != 4097 {
		t.Fatal("native role policy truncated the complete saved workload", len(policy.Definition.DescriptionRules))
	}
	var same entity.InterfaceRolePolicyRecord
	call(a, "interface_role_policy_set", map[string]any{"context_id": f.contextID, "expected_id": policy.ID, "expected_revision": policy.Revision, "definition": policy.Definition}, &same, true)
	if same.ID != policy.ID || same.Revision != policy.Revision || len(same.Definition.DescriptionRules) != 4097 {
		t.Fatal("native complete policy changed identity or population", same.ID, same.Revision, len(same.Definition.DescriptionRules))
	}
	explain(a, entity.InterfaceRoleBackbone)
	explain(b, entity.InterfaceRoleTransit)
	for _, permission := range []string{"entities.read", "metrics.read", "events.read"} {
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permission)
			return err
		})
		call(a, "interface_role_explain", readArgs, nil, false)
		explain(b, entity.InterfaceRoleTransit)
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], permission)
		})
	}
}
