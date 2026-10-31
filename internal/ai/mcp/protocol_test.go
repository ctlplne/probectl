// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func modernRequest(method string, params map[string]any) []byte {
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = map[string]any{metaProtocolVersion: modernProtocolVersion, metaClientCapabilities: map[string]any{}}
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	return raw
}

func TestModernRPCMetadataAndIdentityAreCanonical(t *testing.T) {
	base := modernRequest("tools/list", nil)
	req, failure := decodeRPC(base, false)
	if failure != nil || !req.protocol.modern {
		t.Fatal("optional clientInfo became mandatory")
	}
	for _, tc := range []struct {
		name, old, new string
		code           int
	}{
		{"missing-capabilities", `"io.modelcontextprotocol/clientCapabilities":{}`, `"private/ignored":{}`, codeInvalidParams},
		{"null-capabilities", `"io.modelcontextprotocol/clientCapabilities":{}`, `"io.modelcontextprotocol/clientCapabilities":null`, codeInvalidParams},
		{"missing-version", `"io.modelcontextprotocol/protocolVersion":"2026-07-28"`, `"private/ignored":"2026-07-28"`, codeInvalidParams},
		{"null-id", `"id":1`, `"id":null`, codeInvalidRequest},
		{"fraction-id", `"id":1`, `"id":1.25`, codeInvalidRequest},
		{"duplicate-method", `"method":"tools/list"`, `"method":"tools/list","method":"tools/call"`, codeInvalidRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(strings.Replace(string(base), tc.old, tc.new, 1))
			_, failure := decodeRPC(raw, true)
			if failure == nil || failure.Error.Code != tc.code {
				t.Fatal("malformed modern context accepted", failure)
			}
		})
	}
	unknown := []byte(strings.Replace(string(base), modernProtocolVersion, "2099-01-01", 1))
	_, failure = decodeRPC(unknown, true)
	if failure == nil || failure.Error.Code != codeUnsupportedVersion {
		t.Fatal("version mismatch lost protocol error")
	}
	data, ok := failure.Error.Data.(map[string]any)
	if !ok || data["requested"] != "2099-01-01" {
		t.Fatal("version mismatch omitted exact requested version")
	}
}

func TestRPCIntegerIDsCompareExactlyWithoutExponentAllocation(t *testing.T) {
	for _, same := range [][]string{{"1", "1.0", "10e-1", "0.01e2"}, {"0", "-0", "0e9999999999999999999999"}, {"1000", "1e3", "100000e-2"}, {"-12", "-1.2e1", "-1200e-2"}} {
		first, ok := requestIDKey(json.RawMessage(same[0]))
		if !ok {
			t.Fatal("integer ID refused")
		}
		for _, value := range same {
			next, ok := requestIDKey(json.RawMessage(value))
			if !ok || next != first {
				t.Fatal("numeric ID alias was not canonical", value)
			}
		}
	}
	for _, bad := range []string{"null", "true", "[]", "{}", "1.2", "1e-9999999999999999999999"} {
		if _, ok := requestIDKey(json.RawMessage(bad)); ok {
			t.Fatal("non-integer ID admitted", bad)
		}
	}
	if key, ok := requestIDKey(json.RawMessage("1e9999999999999999999999")); !ok || len(key) > 100 {
		t.Fatal("integer exponent expanded into allocation")
	}
	numeric, _ := requestIDKey(json.RawMessage("1"))
	text, _ := requestIDKey(json.RawMessage(`"1"`))
	if numeric == text {
		t.Fatal("string and numeric IDs collided")
	}
}

func TestModernResultsCarryCompleteContextAndSafeApplicationErrors(t *testing.T) {
	s := newTestServer(&fakeBackend{}, testGate())
	raw := s.Handle(t.Context(), principal("tenant-modern"), modernRequest("server/discover", nil))
	var response struct {
		Result map[string]json.RawMessage `json:"result"`
		Error  *rpcError                  `json:"error"`
	}
	if json.Unmarshal(raw, &response) != nil || response.Error != nil || string(response.Result["resultType"]) != `"complete"` || len(response.Result["_meta"]) == 0 {
		t.Fatal("modern discovery omitted complete metadata")
	}
	raw = s.Handle(t.Context(), nil, modernRequest("ping", nil))
	if rpcErrorCode(raw) != codeModernUnauthorized {
		t.Fatal("modern mode reused legacy reserved application error")
	}
	raw = s.Handle(t.Context(), principal("tenant-modern"), modernRequest("tools/call", map[string]any{"name": "list_tests", "arguments": map[string]any{}}))
	if rpcErrorCode(raw) != codeModernForbidden {
		t.Fatal("modern forbidden code is not outside reserved range")
	}
	legacy := s.Handle(t.Context(), principal("tenant-modern"), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if strings.Contains(string(legacy), "resultType") {
		t.Fatal("legacy response changed protocol shape")
	}
}

func TestModernHTTPHeadersAgreeWithCanonicalBody(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mutate       func(http.Header)
		method       string
		params       map[string]any
		status, code int
	}{
		{"list", nil, "tools/list", nil, 200, 0},
		{"missing-method", func(h http.Header) { h.Del("Mcp-Method") }, "tools/list", nil, 400, codeHeaderMismatch},
		{"mismatched-method", func(h http.Header) { h.Set("Mcp-Method", "tools/call") }, "tools/list", nil, 400, codeHeaderMismatch},
		{"duplicate-version", func(h http.Header) { h.Add("MCP-Protocol-Version", modernProtocolVersion) }, "tools/list", nil, 400, codeHeaderMismatch},
		{"missing-accept", func(h http.Header) { h.Del("Accept") }, "tools/list", nil, 400, codeInvalidRequest},
		{"zero-quality-accept", func(h http.Header) { h.Set("Accept", "application/json, text/event-stream;q=0") }, "tools/list", nil, 400, codeInvalidRequest},
		{"unknown-method", nil, "unknown/method", nil, 404, codeMethodNotFound},
		{"encoded-tool-name", func(h http.Header) { h.Set("Mcp-Name", "=?base64?Zmxvd19leHBsb3Jlcl9zY2hlbWE=?=") }, "tools/call", map[string]any{"name": "flow_explorer_schema", "arguments": map[string]any{}}, 200, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := nativeProbeServer(&nativeBackendProbe{}, nil)
			request := httptest.NewRequest(http.MethodPost, "https://localhost/mcp", strings.NewReader(string(modernRequest(tc.method, tc.params))))
			request.Header.Set("Authorization", "Bearer owned-modern-token")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json, text/event-stream")
			request.Header.Set("MCP-Protocol-Version", modernProtocolVersion)
			request.Header.Set("Mcp-Method", tc.method)
			if tc.mutate != nil {
				tc.mutate(request.Header)
			}
			w := httptest.NewRecorder()
			server.HTTPHandler(fakeAuthn{p: nativePrincipal()}).ServeHTTP(w, request)
			if w.Code != tc.status || rpcErrorCode(w.Body.Bytes()) != tc.code {
				t.Fatal("HTTP protocol validation diverged from body", w.Code, rpcErrorCode(w.Body.Bytes()), w.Body.String())
			}
		})
	}
}

func TestModernRPCUsesExactMemberNames(t *testing.T) {
	base := string(modernRequest("tools/list", nil))
	for _, tc := range []struct{ name, raw string }{
		{"method-alias", strings.Replace(base, `"method":"tools/list"`, `"method":"tools/list","Method":"tools/call"`, 1)},
		{"params-alias", strings.Replace(base, `"params":`, `"Params":{},"params":`, 1)},
		{"params-mask", strings.TrimSuffix(base, "}") + `,"Params":{}}`},
		{"id-alias", strings.Replace(base, `"id":1`, `"id":1,"ID":2`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, failure := decodeRPC([]byte(tc.raw), false)
			if failure != nil || !req.protocol.modern || req.Method != "tools/list" || string(req.ID) != "1" {
				t.Fatal("case alias changed canonical method/context/id or hid modern intent")
			}
		})
	}
	clientAlias := strings.Replace(base, `"_meta":{`, `"_meta":{"io.modelcontextprotocol/clientInfo":{"Name":"alias","version":"1"},`, 1)
	if _, failure := decodeRPC([]byte(clientAlias), false); failure == nil || failure.Error.Code != codeInvalidParams {
		t.Fatal("clientInfo accepted a case alias instead of required name")
	}
}

func TestModernErrorsNeverEchoInvalidRequestIDs(t *testing.T) {
	s := newTestServer(&fakeBackend{}, testGate())
	for _, id := range []string{"null", "true", `{"private":"value"}`, "[]"} {
		raw := strings.Replace(string(modernRequest("tools/list", nil)), `"id":1`, `"id":`+id, 1)
		response := s.Handle(t.Context(), stdioPrincipal(), []byte(raw))
		var envelope map[string]json.RawMessage
		if json.Unmarshal(response, &envelope) != nil || len(envelope["id"]) != 0 || len(envelope["error"]) == 0 || strings.Contains(string(response), "private") {
			t.Fatal("invalid request id escaped in an error response")
		}
	}
}

func TestModernStdioCancellationUsesExactMembersAndIgnoresMalformedNotices(t *testing.T) {
	for _, raw := range []string{
		`{"jsonrpc":"2.0","method":"notifications/progress","Method":"notifications/cancelled","params":{"requestId":1}}`, //nolint:misspell // MCP wire method spelling.
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"RequestId":1}}`,                                   //nolint:misspell // MCP wire method spelling.
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":{}}}`,                       //nolint:misspell // MCP wire method spelling.
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"requestId":2}}`,                     //nolint:misspell // MCP wire method spelling.
	} {
		notification, key := stdioNotification([]byte(raw))
		if !notification || key != "" {
			t.Fatal("malformed or aliased cancellation had an effect")
		}
	}
}
