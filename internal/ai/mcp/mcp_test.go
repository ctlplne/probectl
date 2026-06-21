// SPDX-License-Identifier: LicenseRef-probectl-TBD

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/auth"
)

// testGate is a permissive egress gate for mechanics tests: consent allowed
// for every tenant, no audit sink, no optional masking (secrets are still
// always masked by design). Consent/redaction behavior has its own tests.
func testGate() *ai.EgressGate {
	return ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil }, nil, ai.RedactionPolicy{})
}

// fakeBackend records the tenant it was called with and returns canned data.
type fakeBackend struct {
	mu      sync.Mutex
	calls   []string
	tenants []string
}

func (f *fakeBackend) rec(method string, p *auth.Principal) {
	f.mu.Lock()
	f.calls = append(f.calls, method)
	f.tenants = append(f.tenants, p.TenantID)
	f.mu.Unlock()
}
func (f *fakeBackend) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}
func (f *fakeBackend) ListTests(_ context.Context, p *auth.Principal) (any, error) {
	f.rec("ListTests", p)
	return map[string]any{"tests": []any{}}, nil
}
func (f *fakeBackend) GetPath(_ context.Context, p *auth.Principal, target string) (any, error) {
	f.rec("GetPath", p)
	return map[string]any{"found": true, "target": target}, nil
}
func (f *fakeBackend) GetBGPEvents(_ context.Context, p *auth.Principal, _, _ string, _ int) (any, error) {
	f.rec("GetBGPEvents", p)
	return map[string]any{"events": []any{}}, nil
}
func (f *fakeBackend) QueryFlows(_ context.Context, p *auth.Principal, _, _, _ string, _ int) (any, error) {
	f.rec("QueryFlows", p)
	return map[string]any{"events": []any{}}, nil
}
func (f *fakeBackend) GetIncident(_ context.Context, p *auth.Principal, id string) (any, error) {
	f.rec("GetIncident", p)
	return map[string]any{"id": id}, nil
}
func (f *fakeBackend) CorrelateIncident(_ context.Context, p *auth.Principal, id string) (any, error) {
	f.rec("CorrelateIncident", p)
	return map[string]any{"id": id}, nil
}
func (f *fakeBackend) ExplainDegradation(_ context.Context, p *auth.Principal, q string, _ map[string]string) (any, error) {
	f.rec("ExplainDegradation", p)
	return map[string]any{"root_cause": "x", "question": q}, nil
}

func (f *fakeBackend) ProposeRemediation(_ context.Context, p *auth.Principal, kind, title, _, _, _ string) (any, error) {
	f.rec("ProposeRemediation", p)
	return map[string]any{"state": "proposed", "kind": kind, "title": title}, nil
}

func principal(tenant string, perms ...string) *auth.Principal {
	m := map[string]bool{}
	for _, k := range perms {
		m[k] = true
	}
	return &auth.Principal{TenantID: tenant, Permissions: m}
}

func allPerms() []string {
	return []string{permTestRead, permEventsRead, permIncidentRead, permAIQuery}
}

func handle(t *testing.T, s *Server, p *auth.Principal, id int, method string, params any) map[string]any {
	t.Helper()
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	raw, _ := json.Marshal(req)
	out := s.Handle(context.Background(), p, raw)
	if out == nil {
		return nil
	}
	var resp map[string]any
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal response: %v (%s)", err, out)
	}
	return resp
}

func errCode(resp map[string]any) (int, bool) {
	e, ok := resp["error"].(map[string]any)
	if !ok {
		return 0, false
	}
	c, _ := e["code"].(float64)
	return int(c), true
}

func resultOf(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()
	r, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected a result, got %v", resp)
	}
	return r
}

func TestInitializeAndPing(t *testing.T) {
	s := New(&fakeBackend{}, testGate())
	init := resultOf(t, handle(t, s, principal("t"), 1, "initialize", nil))
	if init["protocolVersion"] != protocolVersion {
		t.Errorf("protocolVersion = %v", init["protocolVersion"])
	}
	if info, _ := init["serverInfo"].(map[string]any); info["name"] != "probectl" {
		t.Errorf("serverInfo = %v", init["serverInfo"])
	}
	if _, isErr := errCode(handle(t, s, principal("t"), 2, "ping", nil)); isErr {
		t.Error("ping should not error")
	}
}

func TestToolsListFilteredByRBAC(t *testing.T) {
	s := New(&fakeBackend{}, testGate())
	// A caller holding only test.read sees only the test.read tools.
	resp := handle(t, s, principal("t", permTestRead), 3, "tools/list", nil)
	tools, _ := resultOf(t, resp)["tools"].([]any)
	got := map[string]bool{}
	for _, raw := range tools {
		got[raw.(map[string]any)["name"].(string)] = true
	}
	if !got["list_tests"] || !got["get_path"] {
		t.Errorf("test.read caller should see list_tests + get_path, got %v", got)
	}
	for _, hidden := range []string{"get_incident", "get_bgp_events", "explain_degradation", "query_flows"} {
		if got[hidden] {
			t.Errorf("tool %q must be hidden from a test.read-only caller", hidden)
		}
	}
}

func TestToolsCallTenantScopedAndForbidden(t *testing.T) {
	fb := &fakeBackend{}
	s := New(fb, testGate())

	// Authorized call: the backend is invoked with the principal's tenant.
	resp := handle(t, s, principal("tenant-a", permTestRead), 4, "tools/call",
		map[string]any{"name": "list_tests"})
	res := resultOf(t, resp)
	if _, ok := res["content"]; !ok {
		t.Errorf("tool result missing content: %v", res)
	}
	if len(fb.tenants) != 1 || fb.tenants[0] != "tenant-a" {
		t.Errorf("backend tenant = %v, want [tenant-a]", fb.tenants)
	}

	// Out-of-scope caller gets nothing: a test.read-only caller cannot call
	// get_incident, and the backend is never reached.
	fb2 := &fakeBackend{}
	s2 := New(fb2, testGate())
	resp = handle(t, s2, principal("tenant-a", permTestRead), 5, "tools/call",
		map[string]any{"name": "get_incident", "arguments": map[string]any{"id": "i1"}})
	if code, _ := errCode(resp); code != codeForbidden {
		t.Errorf("forbidden tool: code = %d, want %d", code, codeForbidden)
	}
	if len(fb2.seen()) != 0 {
		t.Errorf("forbidden tool must not reach the backend, got %v", fb2.seen())
	}
}

func TestToolsCallRequiresTenantBeforeRBAC(t *testing.T) {
	for name, p := range map[string]*auth.Principal{
		"nil principal":  nil,
		"empty tenant":   principal("", permTestRead),
		"tenant missing": &auth.Principal{Permissions: map[string]bool{permTestRead: true}},
	} {
		t.Run(name, func(t *testing.T) {
			fb := &fakeBackend{}
			s := New(fb, testGate())
			resp := handle(t, s, p, 6, "tools/call", map[string]any{"name": "list_tests"})
			if code, _ := errCode(resp); code != codeUnauthorized {
				t.Fatalf("tenantless caller: code = %d, want %d", code, codeUnauthorized)
			}
			if len(fb.seen()) != 0 {
				t.Fatalf("tenantless caller must fail before RBAC/backend dispatch, got %v", fb.seen())
			}
		})
	}
}

func TestAllToolsReachBackend(t *testing.T) {
	fb := &fakeBackend{}
	s := New(fb, testGate())
	p := principal("t", allPerms()...)
	calls := []struct {
		name string
		args map[string]any
	}{
		{"list_tests", nil},
		{"get_path", map[string]any{"target": "x"}},
		{"get_bgp_events", map[string]any{"prefix": "10.0.0.0/24", "limit": 5}},
		{"query_flows", map[string]any{"service": "api"}},
		{"get_incident", map[string]any{"id": "i1"}},
		{"correlate_incident", map[string]any{"id": "i1"}},
		{"explain_degradation", map[string]any{"question": "why slow?"}},
	}
	for i, c := range calls {
		params := map[string]any{"name": c.name}
		if c.args != nil {
			params["arguments"] = c.args
		}
		res := resultOf(t, handle(t, s, p, 100+i, "tools/call", params))
		if res["isError"] == true {
			t.Errorf("%s returned isError: %v", c.name, res)
		}
	}
	want := []string{"ListTests", "GetPath", "GetBGPEvents", "QueryFlows", "GetIncident", "CorrelateIncident", "ExplainDegradation"}
	got := fb.seen()
	if len(got) != len(want) {
		t.Fatalf("backend calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("call %d = %s, want %s", i, got[i], want[i])
		}
	}
}

// TestProposeRemediationToolIsProposalOnly is the prompt-injection guardrail at
// the MCP boundary (S-EE5): the propose_remediation tool requires
// remediation.propose, reaches the backend's PROPOSE path (which can only
// create a proposed proposal), and the catalog exposes NO approve/execute tool
// — so ingested data routed through the AI can never approve or execute.
func TestProposeRemediationToolIsProposalOnly(t *testing.T) {
	fb := &fakeBackend{}
	s := New(fb, testGate())

	// A caller holding remediation.propose can file a proposal.
	res := resultOf(t, handle(t, s, principal("tenant-a", permRemediationPropose), 30, "tools/call",
		map[string]any{"name": "propose_remediation", "arguments": map[string]any{
			"kind": "reroute_suggestion", "title": "reroute around failing hop",
		}}))
	if res["isError"] == true {
		t.Fatalf("propose_remediation returned isError: %v", res)
	}
	if got := fb.seen(); len(got) != 1 || got[0] != "ProposeRemediation" {
		t.Fatalf("backend calls = %v, want [ProposeRemediation]", got)
	}

	// A caller WITHOUT the permission is forbidden and never reaches the backend.
	fb2 := &fakeBackend{}
	s2 := New(fb2, testGate())
	resp := handle(t, s2, principal("tenant-a", permTestRead), 31, "tools/call",
		map[string]any{"name": "propose_remediation", "arguments": map[string]any{
			"kind": "reroute_suggestion", "title": "x",
		}})
	if code, _ := errCode(resp); code != codeForbidden {
		t.Fatalf("propose without permission: code=%d, want %d (forbidden)", code, codeForbidden)
	}
	if len(fb2.seen()) != 0 {
		t.Fatalf("forbidden propose must not reach the backend, got %v", fb2.seen())
	}

	// Structural: there is NO approve/execute/apply tool anywhere in the catalog.
	for _, tl := range buildTools(fb) {
		n := strings.ToLower(tl.Name)
		for _, banned := range []string{"approve", "execute", "apply", "remediate_now", "enact"} {
			if strings.Contains(n, banned) {
				t.Fatalf("MCP catalog exposes a forbidden write/execute tool %q — the AI must only PROPOSE", tl.Name)
			}
		}
	}
}

func TestNoTenantFailsClosed(t *testing.T) {
	s := New(&fakeBackend{}, testGate())
	if code, _ := errCode(handle(t, s, principal(""), 6, "tools/list", nil)); code != codeUnauthorized {
		t.Errorf("tenantless principal: code = %d, want %d", code, codeUnauthorized)
	}
}

func TestToolArgValidationIsError(t *testing.T) {
	s := New(&fakeBackend{}, testGate())
	// get_path with no target → an isError tool result (not a transport error).
	res := resultOf(t, handle(t, s, principal("t", permTestRead), 7, "tools/call",
		map[string]any{"name": "get_path", "arguments": map[string]any{}}))
	if res["isError"] != true {
		t.Errorf("missing required arg should yield an isError result, got %v", res)
	}
}

func TestRateLimit(t *testing.T) {
	fb := &fakeBackend{}
	s := New(fb, testGate(), WithRateLimit(1))
	p := principal("t", permTestRead)
	if _, isErr := errCode(handle(t, s, p, 8, "tools/call", map[string]any{"name": "list_tests"})); isErr {
		t.Fatal("first call should be allowed")
	}
	if code, _ := errCode(handle(t, s, p, 9, "tools/call", map[string]any{"name": "list_tests"})); code != codeRateLimited {
		t.Errorf("second call: code = %d, want %d (rate limited)", code, codeRateLimited)
	}
}

func TestParseError(t *testing.T) {
	s := New(&fakeBackend{}, testGate())
	var resp map[string]any
	_ = json.Unmarshal(s.Handle(context.Background(), principal("t"), []byte("{bad")), &resp)
	if code, _ := errCode(resp); code != codeParse {
		t.Errorf("malformed JSON: code = %d, want %d", code, codeParse)
	}
}

func TestServeStdioRoundTrip(t *testing.T) {
	s := New(&fakeBackend{}, testGate())
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n" +
			`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" + // notification: no reply
			`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")
	var out bytes.Buffer
	if err := s.ServeStdio(context.Background(), in, &out, principal("t", permTestRead)); err != nil {
		t.Fatal(err)
	}
	var lines int
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.TrimSpace(l) != "" {
			lines++
		}
	}
	if lines != 2 { // ping + tools/list replies; the notification produced none
		t.Errorf("got %d reply lines, want 2: %q", lines, out.String())
	}
}

type fakeAuthn struct {
	p   *auth.Principal
	err error
}

func (f fakeAuthn) Authenticate(context.Context, string) (*auth.Principal, error) { return f.p, f.err }

func TestHTTPHandler(t *testing.T) {
	s := New(&fakeBackend{}, testGate())
	h := s.HTTPHandler(fakeAuthn{p: principal("t", permTestRead)})
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Authenticated POST → a JSON-RPC result.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	var jr map[string]any
	_ = json.Unmarshal(data, &jr)
	if _, ok := jr["result"]; !ok {
		t.Errorf("expected a result, got %s", data)
	}

	// Missing token → 401.
	noTok, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(body))
	r2, _ := http.DefaultClient.Do(noTok)
	if r2 != nil {
		r2.Body.Close()
		if r2.StatusCode != http.StatusUnauthorized {
			t.Errorf("missing token: status = %d, want 401", r2.StatusCode)
		}
	}

	// GET → 405.
	r3, _ := http.Get(srv.URL)
	if r3 != nil {
		r3.Body.Close()
		if r3.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("GET: status = %d, want 405", r3.StatusCode)
		}
	}
}

func TestHTTPHandlerRejectsBadToken(t *testing.T) {
	s := New(&fakeBackend{}, testGate())
	h := s.HTTPHandler(fakeAuthn{err: io.EOF})
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Authorization", "Bearer bad")
	resp, _ := http.DefaultClient.Do(req)
	if resp != nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("bad token: status = %d, want 401", resp.StatusCode)
		}
	}
}

func TestHTTPHandlerRejectsOversizedBody(t *testing.T) {
	s := New(&fakeBackend{}, testGate())
	h := s.HTTPHandler(fakeAuthn{p: principal("t", permTestRead)})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(strings.Repeat("x", (1<<20)+1)))
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}
