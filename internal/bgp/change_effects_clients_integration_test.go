// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func proveRouterChangeClients(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, probe routerChangeProbe, original, foreign string, expected sdk.ChangeEffectsResponse) {
	t.Helper()
	code, _ := st.Do(t, reg.cookie, http.MethodPut, "/v1/governance/policy", map[string]any{"ai_remote_egress": true, "redact_export": true})
	if code != http.StatusOK {
		t.Fatal("original-change native client requires explicit audited consent", code)
	}
	code, body := st.Do(t, reg.cookie, http.MethodGet, "/v1/me", nil)
	var me struct {
		UserID   string `json:"user_id"`
		TenantID string `json:"tenant_id"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &me) != nil || me.UserID == "" || me.TenantID != reg.tenantID {
		t.Fatal("original-change client has no current tenant user")
	}
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run("clients/"+wire, func(t *testing.T) {
			issued := strings.Split(strings.TrimSpace(st.Subcommand(t, "mcp-token", "--tenant", reg.tenantID, "--user", me.UserID, "--name", "original-change-"+wire, "--scope", "read,ai.query", "--expires-days", "1")), "\n")
			token := issued[len(issued)-1]
			if wire == "2026-07-28" {
				t.Run("sdk", func(t *testing.T) {
					client := sdk.NewClient(st.BaseURL, sdk.WithHTTPClient(st.Client()), sdk.WithToken(token))
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					request := sdk.GetChangeEffectsRequest{Id: original, From: &expected.Before.From, To: &expected.After.To}
					shipped.Await(t, "original change SDK publication at the exact window", 10*time.Second, func() bool {
						got, err := client.GetChangeEffects(ctx, request)
						var fault *sdk.SDKError
						if errors.As(err, &fault) && fault.StatusCode == http.StatusServiceUnavailable &&
							fault.Message == "change or original source authority changed before publication; retry" {
							return false
						}
						if err != nil || got == nil {
							t.Fatal("original-change generated SDK", err)
						}
						verifyRouterChangeClient(t, st, reg, probe, *got, expected, false)
						return true
					})
				})
				t.Run("cli", func(t *testing.T) {
					var got sdk.ChangeEffectsResponse
					st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": token}, &got, "oncall", "change-effects", original, "--query", "from="+expected.Before.From, "--query", "to="+expected.After.To)
					verifyRouterChangeClient(t, st, reg, probe, got, expected, false)
				})
			}
			input, output := st.MCPStdio(t, "original-change-"+wire+"-"+strings.ReplaceAll(original, ":", "-"), token)
			encoder, decoder := json.NewEncoder(input), json.NewDecoder(output)
			if wire == "2025-11-25" {
				if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": map[string]any{"protocolVersion": wire, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "original-change-client", "version": "1"}}}); err != nil {
					t.Fatal(err)
				}
				var initialization struct {
					Result struct {
						Version string `json:"protocolVersion"`
					} `json:"result"`
				}
				if decoder.Decode(&initialization) != nil || initialization.Result.Version != wire {
					t.Fatal("original-change native client failed protocol negotiation")
				}
				if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
					t.Fatal(err)
				}
			}
			call := func(id string, wantOK bool) {
				t.Helper()
				params := map[string]any{"name": "change_effects", "arguments": map[string]string{"change_id": id, "from": expected.Before.From, "to": expected.After.To}}
				if wire == "2026-07-28" {
					params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": wire, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
				}
				if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}); err != nil {
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
				if decoder.Decode(&reply) != nil {
					t.Fatal("original-change process lost its complete RPC frame")
				}
				hasData := len(reply.Result.Data) > 0 && string(reply.Result.Data) != "null"
				success := len(reply.Error) == 0 && !reply.Result.IsError && hasData
				if success != wantOK || !success && hasData {
					t.Fatal("original-change process lost current tenant/credential authority", success, wantOK)
				}
				if !success {
					return
				}
				if wire == "2026-07-28" && reply.Result.ResultType != "complete" || wire == "2025-11-25" && reply.Result.ResultType != "" || len(reply.Result.Content) != 1 || strings.TrimSpace(reply.Result.Content[0].Text) != strings.TrimSpace(string(reply.Result.Data)) {
					t.Fatal("original-change process changed its complete protocol framing")
				}
				var got sdk.ChangeEffectsResponse
				if json.Unmarshal(reply.Result.Data, &got) != nil {
					t.Fatal("original-change process emitted an invalid response")
				}
				verifyRouterChangeClient(t, st, reg, probe, got, expected, true)
			}
			call(original, true)
			call(foreign, false)
			pool, err := pgxpool.New(t.Context(), st.AdminDSN)
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			if err := store.NewMCPTokens(pool).RevokeForUser(t.Context(), reg.tenantID, me.UserID); err != nil {
				t.Fatal(err)
			}
			call(original, false)
		})
	}
}

func verifyRouterChangeClient(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, probe routerChangeProbe, got, expected sdk.ChangeEffectsResponse, native bool) {
	t.Helper()
	wantConfig := expected.Original.Config
	if native && wantConfig.Binding != nil && got.Original.Config.Binding != nil {
		// Native free-text agent/source labels retain mandatory redaction.
		// Typed canonical IDs, pair hashes, versions and clocks remain exact;
		// the RLS oracle below checks the actual sender on every measurement.
		binding := *wantConfig.Binding
		binding.AgentId = got.Original.Config.Binding.AgentId
		binding.SourceRef = got.Original.Config.Binding.SourceRef
		wantConfig.Binding = &binding
	}
	if got.Original.Id != expected.Original.Id || got.Original.TenantId != reg.tenantID || !reflect.DeepEqual(got.Original.Routing, expected.Original.Routing) || !reflect.DeepEqual(got.Original.Config, wantConfig) || len(got.Tests) != 1 || got.Tests[0].TestId != probe.test {
		t.Fatal("original-change client lost exact original references or selected another tenant")
	}
	verifyRouterOriginalTestPeriod(t, st, reg, probe, got.Tests[0].Before)
	verifyRouterOriginalTestPeriod(t, st, reg, probe, got.Tests[0].After)
}
