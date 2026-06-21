// SPDX-License-Identifier: LicenseRef-probectl-TBD

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/auth"
)

const (
	maxMCPHandleFuzzBody     = 64 * 1024
	maxMCPHandleFuzzResponse = 2*maxMCPHandleFuzzBody + 4096
)

func FuzzMCPHandle(f *testing.F) {
	for _, seed := range []struct {
		principal string
		body      string
	}{
		{"all", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`},
		{"all", `{"jsonrpc":"2.0","id":"ping-1","method":"ping"}`},
		{"all", `{"jsonrpc":"2.0","method":"notifications/initialized"}`},
		{"all", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`},
		{"all", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_tests","arguments":{}}}`},
		{"all", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_path","arguments":{"target":"https://api.example.test"}}}`},
		{"all", `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_incident","arguments":{"id":"inc-1"}}}`},
		{"all", `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"explain_degradation","arguments":{"question":"why is api slow?","subject":{"target":"api"}}}}`},
		{"all", `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"propose_remediation","arguments":{"kind":"reroute_suggestion","title":"reroute around failed hop"}}}`},
		{"limited", `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"get_incident","arguments":{"id":"inc-foreign"}}}`},
		{"tenantless", `{"jsonrpc":"2.0","id":9,"method":"tools/list"}`},
		{"nil", `{"jsonrpc":"2.0","id":10,"method":"tools/list"}`},
		{"all", `{"jsonrpc":"2.0","id":{"nested":["bad"]},"method":"tools/call","params":{"name":"get_path","arguments":[]}}`},
		{"all", `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":123,"arguments":{"target":true}}}`},
		{"all", `{"jsonrpc":"2.0","id":12,"method":"unknown","params":{"x":[1,2,3]}}`},
		{"all", `{bad json`},
		{"all", `[]`},
		{"all", `null`},
	} {
		f.Add(seed.principal, []byte(seed.body))
	}

	f.Fuzz(func(t *testing.T, principalMode string, raw []byte) {
		if len(raw) > maxMCPHandleFuzzBody {
			t.Skip()
		}

		var req rpcRequest
		reqOK := json.Unmarshal(raw, &req) == nil
		backend := &mcpFuzzBackend{}
		server := New(backend, testGate(), WithRateLimit(0))
		principal := mcpFuzzPrincipal(principalMode)

		resp := server.Handle(context.Background(), principal, raw)
		if principal == nil || principal.TenantID == "" {
			if backend.calls != 0 {
				t.Fatalf("tenantless MCP caller reached backend %d time(s)", backend.calls)
			}
		}
		if resp == nil {
			if reqOK && len(req.ID) == 0 {
				return
			}
			t.Fatalf("nil response for non-notification input: %q", raw)
		}
		if len(resp) > maxMCPHandleFuzzResponse {
			t.Fatalf("response too large: got %d bytes from %d-byte request", len(resp), len(raw))
		}

		var parsed rpcResponse
		if err := json.Unmarshal(resp, &parsed); err != nil {
			t.Fatalf("MCP response is not valid JSON: %v: %s", err, resp)
		}
		if parsed.JSONRPC != jsonRPCVersion {
			t.Fatalf("jsonrpc = %q, want %q in response %s", parsed.JSONRPC, jsonRPCVersion, resp)
		}
		if parsed.Error != nil && parsed.Result != nil {
			t.Fatalf("response contains both result and error: %s", resp)
		}
		if reqOK && len(req.ID) > 0 && (principal == nil || principal.TenantID == "") {
			if parsed.Error == nil || parsed.Error.Code != codeUnauthorized {
				t.Fatalf("tenantless request code = %+v, want unauthorized; response %s", parsed.Error, resp)
			}
		}
	})
}

func mcpFuzzPrincipal(mode string) *auth.Principal {
	switch mode {
	case "nil":
		return nil
	case "tenantless":
		return &auth.Principal{UserID: "u-fuzz", Permissions: mcpFuzzPermissions(permTestRead, permEventsRead, permIncidentRead, permAIQuery, permRemediationPropose)}
	case "limited":
		return &auth.Principal{TenantID: "tenant-fuzz", UserID: "u-fuzz", Permissions: mcpFuzzPermissions(permTestRead)}
	default:
		return &auth.Principal{TenantID: "tenant-fuzz", UserID: "u-fuzz", Permissions: mcpFuzzPermissions(permTestRead, permEventsRead, permIncidentRead, permAIQuery, permRemediationPropose)}
	}
}

func mcpFuzzPermissions(perms ...string) map[string]bool {
	out := make(map[string]bool, len(perms))
	for _, perm := range perms {
		out[perm] = true
	}
	return out
}

type mcpFuzzBackend struct {
	calls int
}

func (b *mcpFuzzBackend) rec() {
	b.calls++
}

func (b *mcpFuzzBackend) ListTests(context.Context, *auth.Principal) (any, error) {
	b.rec()
	return map[string]any{"tests": []any{}}, nil
}

func (b *mcpFuzzBackend) GetPath(_ context.Context, _ *auth.Principal, target string) (any, error) {
	b.rec()
	return map[string]any{"target": target, "hops": []any{}}, nil
}

func (b *mcpFuzzBackend) GetBGPEvents(context.Context, *auth.Principal, string, string, int) (any, error) {
	b.rec()
	return map[string]any{"events": []any{}}, nil
}

func (b *mcpFuzzBackend) QueryFlows(context.Context, *auth.Principal, string, string, string, int) (any, error) {
	b.rec()
	return map[string]any{"flows": []any{}}, nil
}

func (b *mcpFuzzBackend) GetIncident(_ context.Context, _ *auth.Principal, id string) (any, error) {
	b.rec()
	return map[string]any{"id": id}, nil
}

func (b *mcpFuzzBackend) CorrelateIncident(_ context.Context, _ *auth.Principal, id string) (any, error) {
	b.rec()
	return map[string]any{"id": id, "signals": []any{}}, nil
}

func (b *mcpFuzzBackend) ExplainDegradation(_ context.Context, _ *auth.Principal, question string, subject map[string]string) (any, error) {
	b.rec()
	return map[string]any{"question": question, "subject": subject, "root_cause": "fuzz-safe"}, nil
}

func (b *mcpFuzzBackend) ProposeRemediation(_ context.Context, _ *auth.Principal, kind, title, rationale, target, incidentID string) (any, error) {
	b.rec()
	return map[string]any{
		"state":       "proposed",
		"kind":        kind,
		"title":       title,
		"rationale":   rationale,
		"target":      target,
		"incident_id": incidentID,
	}, nil
}
