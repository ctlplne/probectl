// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func interfaceRoleNativeTLSCaller(t *testing.T, f *roleExplanationAPIFixture, wire string) func(tenant, tool string, args any, target any, wantOK bool) {
	t.Helper()
	return interfaceRoleTLSCaller(t, f, wire, true)
}

func interfaceRoleTLSCaller(t *testing.T, f *roleExplanationAPIFixture, wire string, exactText bool) func(tenant, tool string, args any, target any, wantOK bool) {
	t.Helper()
	// Match config.Load's shipped defaults, rather than a zero-value fixture
	// that explicitly disables the configurable IP/hostname/PII masks.
	cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
	server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, pathstore.NewMemory(), 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), f.server.aiSources())
	socket := httptest.NewTLSServer(server.HTTPHandler(NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)))
	t.Cleanup(socket.Close)
	if wire == "2025-11-25" {
		for _, tenant := range f.tenants {
			proveLegacyMCPInitializationTLS(t, socket, f.tokens[tenant])
		}
	}
	return func(tenant, tool string, args any, target any, wantOK bool) {
		t.Helper()
		started := time.Now()
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
		// Transport authentication rejects a revoked bearer before JSON-RPC.
		// Require the exact public refusal and challenge, with no tool payload.
		if !wantOK && response.StatusCode == http.StatusUnauthorized {
			if string(raw) != "invalid token\n" || response.Header.Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("native role credential refusal changed its bounded public response")
			}
			return
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
		if err := json.Unmarshal(raw, &reply); err != nil {
			t.Fatalf("native %s %s response is not a complete RPC frame: status=%d bytes=%d elapsed=%s: %v", wire, tool, response.StatusCode, len(raw), time.Since(started), err)
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
		if len(reply.Result.Content) != 1 {
			t.Fatal("tool result lost its complete text representation")
		}
		text, data := bytes.TrimSpace([]byte(reply.Result.Content[0].Text)), bytes.TrimSpace(reply.Result.Data)
		if !exactText {
			// Generic tools deliberately pretty-print text; structured RPC JSON
			// is compact. Remove whitespace only, preserving every numeric and
			// string byte. Native tools retain the original byte-for-byte oracle.
			var compactText, compactData bytes.Buffer
			if err := json.Compact(&compactText, text); err != nil {
				t.Fatal(err)
			}
			if err := json.Compact(&compactData, data); err != nil {
				t.Fatal(err)
			}
			text, data = compactText.Bytes(), compactData.Bytes()
		}
		if !bytes.Equal(text, data) {
			t.Fatal("tool text and structured results disagree")
		}

		if target != nil && json.Unmarshal(reply.Result.Data, target) != nil {
			t.Fatal("native role result lost its typed complete representation")
		}
	}
}

func seedInterfaceRoleMCPConsent(f *roleExplanationAPIFixture) {
	f.t.Helper()
	for _, tenant := range f.tenants {
		if err := tenancy.InProvider(f.t.Context(), f.pool, func(ctx context.Context, q tenancy.Querier) error {
			_, err := q.Exec(ctx, `INSERT INTO tenant_governance (tenant_id,ai_remote_egress) VALUES($1,true) ON CONFLICT(tenant_id) DO UPDATE SET ai_remote_egress=true`, tenant)
			return err
		}); err != nil {
			f.t.Fatal(err)
		}
	}
}

func proveLegacyMCPInitializationTLS(t *testing.T, socket *httptest.Server, token string) {
	t.Helper()
	frames := []string{
		`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"owned-pg-client","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	for index, frame := range frames {
		r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL, strings.NewReader(frame))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("MCP-Protocol-Version", "2025-11-25")
		response, err := socket.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
		if err != nil || response.Header.Get("MCP-Session-Id") != "" {
			t.Fatal("legacy initialization failed or created session authority")
		}
		if index == 0 {
			var result struct {
				Result struct {
					Version string `json:"protocolVersion"`
				} `json:"result"`
			}
			if response.StatusCode != 200 || json.Unmarshal(raw, &result) != nil || result.Result.Version != "2025-11-25" {
				t.Fatal("actual PG HTTP legacy initialization version mismatch")
			}
		} else if response.StatusCode != 202 || len(raw) != 0 {
			t.Fatal("actual PG HTTP initialized notification not accepted")
		}
	}
}
