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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type interfaceRoleStdioClient struct {
	input   *io.PipeWriter
	decoder *json.Decoder
}

func openInterfaceRoleStdio(t *testing.T, server *mcp.Server, authenticator mcp.Authenticator, token, wire string) *interfaceRoleStdioClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	initial, err := authenticator.Authenticate(ctx, token)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	inputR, inputW := io.Pipe()
	outputR, outputW := io.Pipe()
	closePipes := func() { _ = inputR.Close(); _ = inputW.Close(); _ = outputR.Close(); _ = outputW.Close() }
	done := make(chan error, 1)
	go func() { <-ctx.Done(); closePipes() }()
	go func() {
		defer outputW.Close()
		done <- server.ServeAuthenticatedStdio(ctx, inputR, outputW, initial, func(ctx context.Context) (*auth.Principal, error) { return authenticator.Authenticate(ctx, token) })
	}()
	t.Cleanup(func() {
		_ = inputW.Close()
		select {
		case err := <-done:
			if err != nil && ctx.Err() == nil {
				t.Error("role stdio did not drain cleanly", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("role stdio did not drain before cleanup")
		}
		cancel()
		closePipes()
	})
	client := &interfaceRoleStdioClient{input: inputW, decoder: json.NewDecoder(outputR)}
	if wire == "2025-11-25" {
		frame, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": map[string]any{"protocolVersion": wire, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "owned-role-client", "version": "1"}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inputW.Write(append(frame, '\n')); err != nil {
			t.Fatal(err)
		}
		var initialized struct {
			Result struct {
				Version string `json:"protocolVersion"`
			} `json:"result"`
		}
		if client.decoder.Decode(&initialized) != nil || initialized.Result.Version != wire {
			t.Fatal("role stdio did not negotiate its legacy revision")
		}
		if _, err := inputW.Write([]byte("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")); err != nil {
			t.Fatal(err)
		}
	}
	return client
}

func (c *interfaceRoleStdioClient) call(t *testing.T, wire, tool string, args, target any, wantOK bool) {
	t.Helper()
	params := map[string]any{"name": tool, "arguments": args}
	if wire == "2026-07-28" {
		params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": wire, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
	}
	frame, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.input.Write(append(frame, '\n')); err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError    bool            `json:"isError"`
			ResultType string          `json:"resultType"`
			Data       json.RawMessage `json:"structuredContent"`
			Content    []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := c.decoder.Decode(&reply); err != nil {
		t.Fatal("role stdio lost its complete RPC frame", err)
	}
	ok := len(reply.Error) == 0 && !reply.Result.IsError && len(reply.Result.Data) > 0 && string(reply.Result.Data) != "null"
	if ok != wantOK {
		t.Fatalf("role stdio current authority mismatch for %s: success=%v expected=%v", tool, ok, wantOK)
	}
	if !ok {
		if len(reply.Result.Data) > 0 && string(reply.Result.Data) != "null" {
			t.Fatal("refused role stdio frame disclosed structured data")
		}
		return
	}
	if (wire == "2026-07-28" && reply.Result.ResultType != "complete") || (wire == "2025-11-25" && reply.Result.ResultType != "") {
		t.Fatal("role stdio result used the wrong protocol revision")
	}
	if len(reply.Result.Content) != 1 || strings.TrimSpace(reply.Result.Content[0].Text) != strings.TrimSpace(string(reply.Result.Data)) {
		t.Fatal("role stdio text and structured results disagree")
	}
	if target != nil && json.Unmarshal(reply.Result.Data, target) != nil {
		t.Fatal("role stdio lost its typed complete result")
	}
}

// Actual persistent stdio streams, token refresh, RLS/configuration and source
// reads. ixpfx/SNMP/BMP facts are modeled; shipped-process/router proof is owed.
func TestInterfaceRoleStdioKeepsWholePoliciesAndRechecksCredentialWithinStream(t *testing.T) {
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(wire, func(t *testing.T) {
			f := newRoleExplanationAPIFixture(t)
			seedInterfaceRoleMCPConsent(f)
			a, b := f.tenants[0], f.tenants[1]
			f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
				configuration := store.InterfaceRoleConfiguration{}
				old, err := configuration.Policy(ctx, sc, f.contextID, roleExplanationStoreBudget())
				if err != nil {
					return err
				}
				_, err = configuration.PutPolicy(ctx, sc, f.contextID, old.ID, old.Revision, entity.InterfaceRolePolicyDefinition{}, roleExplanationStoreBudget())
				return err
			})
			f.in(b, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := (store.InterfaceRoleConfiguration{}).PutOverride(ctx, sc, f.contextID, f.interfaceID, "", "0", entity.InterfaceRolePrivate)
				return err
			})
			ix := roleIXEnricher(t, time.Now().UTC().Add(-time.Minute), "10.42.0.0/24")
			f.server.WithOpenDataStatus(ix, nil, nil)
			cfg := &config.Config{}
			server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, pathstore.NewMemory(), 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
			authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
			first, second := openInterfaceRoleStdio(t, server, authenticator, f.tokens[a], wire), openInterfaceRoleStdio(t, server, authenticator, f.tokens[b], wire)
			args := map[string]any{"context_id": f.contextID, "interface_id": f.interfaceID}
			var explanation interfaceRoleExplanation
			first.call(t, wire, "interface_role_explain", args, &explanation, true)
			if explanation.TenantID != a || explanation.Role != entity.InterfaceRoleIX || !strings.Contains(strings.Join(explanation.Sources, ","), "/snapshot/"+ix.IXPrefixes(time.Now()).Version) {
				t.Fatal("stdio role lost the owned IX generation", explanation)
			}
			second.call(t, wire, "interface_role_explain", args, &explanation, true)
			if explanation.TenantID != b || explanation.Role != entity.InterfaceRolePrivate {
				t.Fatal("stdio role crossed tenant source or override authority", explanation)
			}
			saveCompleteRoleExplanationPolicy(f, a)
			var expected, got entity.InterfaceRolePolicyRecord
			f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
				// Model a valid possible generator output whose numeric prefix
				// also passes a PAN checksum. It remains an opaque UUID,
				// without changing any rule/pattern, order or population.
				if _, err := sc.Q.Exec(ctx, `UPDATE interface_role_policies SET definition=jsonb_set(definition,'{description_rules,0,id}',to_jsonb($3::text)) WHERE tenant_id=$1 AND context_id=$2`, a, f.contextID, "40000000-0000-4004-8000-abcdefabcdef"); err != nil {
					return err
				}
				var err error
				expected, err = (store.InterfaceRoleConfiguration{}).Policy(ctx, sc, f.contextID, interfaceRoleStoreBudget(flowstore.DefaultExplorerBudget()))
				return err
			})
			first.call(t, wire, "interface_role_policy", map[string]any{"context_id": f.contextID}, &got, true)
			if got.TenantID != a || len(got.Definition.DescriptionRules) != 4097 || !reflect.DeepEqual(got.Definition, expected.Definition) || got.ID != expected.ID || got.Revision != expected.Revision {
				t.Log("role policy identity/count diagnostics", got.TenantID == a, got.ID == expected.ID, got.Revision == expected.Revision, len(got.Definition.DescriptionRules), len(expected.Definition.DescriptionRules), got.Definition.ProviderASNs, expected.Definition.ProviderASNs, got.Definition.CustomerASNs, expected.Definition.CustomerASNs)
				for i, rule := range got.Definition.DescriptionRules {
					if i < len(expected.Definition.DescriptionRules) && rule != expected.Definition.DescriptionRules[i] {
						original := expected.Definition.DescriptionRules[i]
						t.Log("synthetic rule difference", i, "same_id", rule.ID == original.ID, "same_role", rule.Role == original.Role, "pattern_bytes", len(rule.Pattern), len(original.Pattern), "rendered_synthetic_pattern", rule.Pattern)
						break
					}
				}
				t.Fatal("stdio role changed complete policy values or exact identity")
			}
			f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='events.read'`, a, f.roles[a])
				return err
			})
			first.call(t, wire, "interface_role_explain", args, nil, false)
			second.call(t, wire, "interface_role_explain", args, &explanation, true)
			if explanation.TenantID != b || explanation.Role != entity.InterfaceRolePrivate {
				t.Fatal("stdio role refusal changed the paired tenant")
			}
			f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
				return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], "events.read")
			})
			first.call(t, wire, "interface_role_explain", args, &explanation, true)
			if explanation.TenantID != a || explanation.Role != entity.InterfaceRoleBackbone {
				t.Fatal("stdio role failed a fresh current authority recovery")
			}
			if err := store.NewMCPTokens(f.pool).RevokeForUser(t.Context(), a, f.users[a]); err != nil {
				t.Fatal(err)
			}
			first.call(t, wire, "interface_role_explain", args, nil, false)
			second.call(t, wire, "interface_role_explain", args, &explanation, true)
			if explanation.TenantID != b || explanation.Role != entity.InterfaceRolePrivate {
				t.Fatal("stdio credential revocation changed the paired tenant")
			}
		})
	}
}
