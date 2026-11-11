// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// The actual compiled control processes load the same current source stores,
// IX files, redaction policy and user credentials as the HTTPS service. Keep
// each connection open through user-token revocation to detect stale grants.
func provePeeringRouterStdio(t *testing.T, st *shipped.Stack, registrations []edgeFlowRegistration, ids []map[uint32]string, links []roleRouterLink, input flow.PeeringEstimateInput) {
	t.Helper()
	pool, err := pgxpool.New(t.Context(), st.AdminDSN)
	if err != nil {
		t.Fatal("owned peering process credential store", err)
	}
	defer pool.Close()
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run("peering-stdio/"+wire, func(t *testing.T) {
			type client struct {
				encoder *json.Encoder
				decoder *json.Decoder
				user    string
			}
			clients := make([]client, len(registrations))
			for lane, reg := range registrations {
				code, _ := st.Do(t, reg.cookie, http.MethodPut, "/v1/governance/policy", map[string]any{"ai_remote_egress": true, "redact_export": true})
				if code != http.StatusOK {
					t.Fatal("peering process requires explicit audited tenant consent", code)
				}
				code, raw := st.Do(t, reg.cookie, http.MethodGet, "/v1/me", nil)
				var me struct {
					UserID   string `json:"user_id"`
					TenantID string `json:"tenant_id"`
				}
				if code != http.StatusOK || json.Unmarshal(raw, &me) != nil || me.UserID == "" || me.TenantID != reg.tenantID {
					t.Fatal("peering process credential has no current tenant user")
				}
				issued := strings.Split(strings.TrimSpace(st.Subcommand(t, "mcp-token", "--tenant", reg.tenantID, "--user", me.UserID, "--name", "peering-process-"+wire, "--scope", "read,ai.query", "--expires-days", "1")), "\n")
				sink, source := st.MCPStdio(t, fmt.Sprintf("peering-stdio-%s-%d", wire, lane), issued[len(issued)-1])
				c := client{encoder: json.NewEncoder(sink), decoder: json.NewDecoder(source), user: me.UserID}
				if wire == "2025-11-25" {
					if err := c.encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": map[string]any{"protocolVersion": wire, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "owned-peering-client", "version": "1"}}}); err != nil {
						t.Fatal(err)
					}
					var initialized struct {
						Result struct {
							Version string `json:"protocolVersion"`
						} `json:"result"`
					}
					if c.decoder.Decode(&initialized) != nil || initialized.Result.Version != wire {
						t.Fatal("shipped peering process lost protocol negotiation")
					}
					if err := c.encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
						t.Fatal(err)
					}
				}
				clients[lane] = c
			}
			call := func(lane int, selected flow.PeeringEstimateInput, wantOK bool) {
				t.Helper()
				params := map[string]any{"name": "flow_peering_estimate", "arguments": selected}
				if wire == "2026-07-28" {
					params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": wire, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
				}
				if err := clients[lane].encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}); err != nil {
					t.Fatal("shipped peering process input", err)
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
				if clients[lane].decoder.Decode(&reply) != nil {
					t.Fatal("shipped peering process lost its complete RPC frame")
				}
				data := reply.Result.Data
				success := len(reply.Error) == 0 && !reply.Result.IsError && len(data) > 0 && string(data) != "null"
				if success != wantOK || !wantOK && len(data) > 0 && string(data) != "null" {
					t.Fatal("shipped peering process retained foreign or revoked source authority", success, wantOK)
				}
				if !success {
					return
				}
				if wire == "2026-07-28" && reply.Result.ResultType != "complete" || wire == "2025-11-25" && reply.Result.ResultType != "" || len(reply.Result.Content) != 1 || strings.TrimSpace(reply.Result.Content[0].Text) != strings.TrimSpace(string(data)) {
					t.Fatal("shipped peering process lost version or complete text/structured parity")
				}
				var out flow.PeeringEstimateResponse
				if json.Unmarshal(data, &out) != nil || !peeringRouterHandMatches(out, registrations[lane], ids[lane], links, lane) || out.Direction != selected.Direction {
					t.Fatal("shipped peering process changed the original source-joined hand p95")
				}
			}
			for lane, reg := range registrations {
				selected := input
				selected.ContextID, selected.InterfaceID = reg.contextID, ids[lane][links[1].index]
				for _, direction := range []string{"inbound", "outbound"} {
					selected.Direction = direction
					call(lane, selected, true)
				}
				selected.ContextID, selected.InterfaceID = registrations[1-lane].contextID, ids[1-lane][links[1].index]
				call(lane, selected, false)
			}
			if err := store.NewMCPTokens(pool).RevokeForUser(t.Context(), registrations[0].tenantID, clients[0].user); err != nil {
				t.Fatal("owned peering process credential revocation", err)
			}
			for lane, reg := range registrations {
				selected := input
				selected.ContextID, selected.InterfaceID = reg.contextID, ids[lane][links[1].index]
				call(lane, selected, lane != 0)
			}
		})
	}
}
