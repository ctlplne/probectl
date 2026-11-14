// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func proveRouterPathStdio(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, test, foreign string, from, to time.Time, expected *sdk.PathInterfaceHealth, wire string) {
	t.Helper()
	code, _ := st.Do(t, reg.cookie, http.MethodPut, "/v1/governance/policy", map[string]any{"ai_remote_egress": true, "redact_export": true})
	if code != http.StatusOK {
		t.Fatal("path process requires explicit audited tenant consent", code)
	}
	code, body := st.Do(t, reg.cookie, http.MethodGet, "/v1/me", nil)
	var identity struct {
		UserID   string `json:"user_id"`
		TenantID string `json:"tenant_id"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &identity) != nil || identity.UserID == "" || identity.TenantID != reg.tenantID {
		t.Fatal("path process has no current tenant user")
	}
	issued := strings.Split(strings.TrimSpace(st.Subcommand(t, "mcp-token", "--tenant", reg.tenantID, "--user", identity.UserID, "--name", "path-process-"+wire, "--scope", "read,ai.query", "--expires-days", "1")), "\n")
	token := issued[len(issued)-1]
	if wire == "2026-07-28" {
		t.Run("sdk", func(t *testing.T) {
			fromText, toText, include := from.Format(time.RFC3339Nano), to.Format(time.RFC3339Nano), true
			client := sdk.NewClient(st.BaseURL, sdk.WithHTTPClient(st.Client()), sdk.WithToken(token))
			result, err := client.GetPathEntities(t.Context(), sdk.GetPathEntitiesRequest{Id: test, IncludeHealth: &include, HealthFrom: &fromText, HealthTo: &toText})
			if err != nil || result == nil {
				t.Fatal("routed path generated SDK", err)
			}
			data, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			verifyRouterPathOriginals(t, data, reg, expected)
		})
		t.Run("cli", func(t *testing.T) {
			command := exec.Command(st.Binary(t, "probectl"), "--json", "entities", "path-resolve", test, "--query", "include_health=true", "--query", "health_from="+from.Format(time.RFC3339Nano), "--query", "health_to="+to.Format(time.RFC3339Nano))
			command.Dir = st.Dir
			command.Env = append(os.Environ(), "PROBECTL_API_URL="+st.BaseURL, "PROBECTL_API_TOKEN="+token, "PROBECTL_CA_FILE="+st.CAFile)
			data, err := command.Output()
			if err != nil {
				t.Fatal("routed path compiled CLI", err)
			}
			verifyRouterPathOriginals(t, data, reg, expected)
		})
	}
	input, output := st.MCPStdio(t, fmt.Sprintf("path-stdio-%s-%s", wire, reg.tenantID), token)
	encoder, decoder := json.NewEncoder(input), json.NewDecoder(output)
	if wire == "2025-11-25" {
		if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": map[string]any{"protocolVersion": wire, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "owned-path-client", "version": "1"}}}); err != nil {
			t.Fatal(err)
		}
		var initialization struct {
			Result struct {
				Version string `json:"protocolVersion"`
			} `json:"result"`
		}
		if decoder.Decode(&initialization) != nil || initialization.Result.Version != wire {
			t.Fatal("path process did not negotiate its original protocol")
		}
		if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
			t.Fatal(err)
		}
	}
	call := func(tool, id string, wantOK bool) json.RawMessage {
		t.Helper()
		args := map[string]any{"test_id": id, "health_from": from.Format(time.RFC3339Nano), "health_to": to.Format(time.RFC3339Nano)}
		if tool == "path_interface_health_explain" {
			args["question"] = "Explain original path interface observations and operator archive changes without assuming causation."
		}
		params := map[string]any{"name": tool, "arguments": args}
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
		if err := decoder.Decode(&reply); err != nil {
			t.Fatal("path process did not emit a complete RPC frame", err)
		}
		success := len(reply.Error) == 0 && !reply.Result.IsError && len(reply.Result.Data) > 0 && string(reply.Result.Data) != "null"
		if success != wantOK {
			t.Fatal("path process lost original tenant/current authority", success, wantOK)
		}
		if !success {
			if len(reply.Result.Data) > 0 && string(reply.Result.Data) != "null" || len(reply.Error) == 0 && !reply.Result.IsError {
				t.Fatal("path refusal disclosed source data or silently omitted execution")
			}
			return nil
		}
		if wire == "2026-07-28" && reply.Result.ResultType != "complete" || wire == "2025-11-25" && reply.Result.ResultType != "" {
			t.Fatal("path process returned the wrong protocol framing")
		}
		if len(reply.Result.Content) != 1 || !bytes.Equal(bytes.TrimSpace([]byte(reply.Result.Content[0].Text)), bytes.TrimSpace(reply.Result.Data)) {
			t.Fatal("native path process text and structured originals disagree")
		}
		return reply.Result.Data
	}
	verifyRouterPathOriginals(t, call("path_interface_health", test, true), reg, expected)
	var answer ai.Answer
	if json.Unmarshal(call("path_interface_health_explain", test, true), &answer) != nil || len(answer.Evidence) != 1 || !answer.RootCauseGrounded || len(answer.RootCauseCitations) == 0 || answer.RootCauseCitations[0].EvidenceID != answer.Evidence[0].ID {
		t.Fatal("shipped path process lost its original cited evidence")
	}
	encoded, err := json.Marshal(answer.Evidence[0].Fields["path_health"])
	if err != nil {
		t.Fatal(err)
	}
	verifyRouterPathOriginals(t, encoded, reg, expected)
	call("path_interface_health", foreign, false)
	pool, err := pgxpool.New(t.Context(), st.AdminDSN)
	if err != nil {
		t.Fatal("owned path token store", err)
	}
	defer pool.Close()
	if err := store.NewMCPTokens(pool).RevokeForUser(t.Context(), reg.tenantID, identity.UserID); err != nil {
		t.Fatal("owned path process credential revocation", err)
	}
	call("path_interface_health", test, false)
}

func verifyRouterPathOriginals(t *testing.T, encoded []byte, reg edgeFlowRegistration, expected *sdk.PathInterfaceHealth) {
	t.Helper()
	var result routerPathHealth
	if json.Unmarshal(encoded, &result) != nil || result.ContextID != reg.contextID {
		t.Fatal("shipped path process changed the original context")
	}
	for _, item := range result.Items {
		if item.Health == nil || item.Health.InterfaceId != expected.InterfaceId || item.Health.DeviceId != reg.deviceID {
			continue
		}
		if !reflect.DeepEqual(item.Health.Counters, expected.Counters) || len(item.Health.ConfigChanges) != len(expected.ConfigChanges) {
			t.Fatal("shipped process changed or omitted original counter words, clocks or receipts")
		}
		for i, ref := range item.Health.ConfigChanges {
			want := expected.ConfigChanges[i]
			if ref.Id != want.Id || ref.ContentHash != want.ContentHash || ref.PreviousId != want.PreviousId || ref.PreviousHash != want.PreviousHash || ref.Version != want.Version || ref.Binding.ContextId != reg.contextID || ref.Binding.DeviceEntityId != reg.deviceID || ref.ObservedAt != want.ObservedAt || ref.Binding.BoundAt != want.Binding.BoundAt {
				t.Fatal("shipped process changed an original operator archive reference")
			}
		}
		return
	}
	t.Fatal("shipped path process omitted the original routed interface")
}
