// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
)

// testGate is a permissive egress gate for mechanics tests: consent allowed
// for every tenant, a successful durable-audit seam, and no optional masking
// (secrets are still always masked by design). Consent/redaction and audit
// failure behavior have their own tests.
func testGate() *ai.EgressGate {
	return ai.NewEgressGate(
		func(context.Context, string) (bool, error) { return true, nil },
		func(context.Context, ai.EgressEvent) error { return nil },
		ai.RedactionPolicy{},
	)
}

func newTestServer(backend Backend, gate *ai.EgressGate, opts ...Option) *Server {
	all := append([]Option{
		WithCallAudit(func(context.Context, CallEvent) error { return nil }),
	}, opts...)
	return New(backend, gate, all...)
}

// fakeBackend records the tenant it was called with and returns canned data.
type fakeBackend struct {
	mu              sync.Mutex
	calls           []string
	tenants         []string
	listTestsResult *TestsResult
	listTestsErr    error
}

type sourceBudgetMarshalProbe struct {
	Nodes  []struct{}
	Called *bool
}

func (p sourceBudgetMarshalProbe) MarshalJSON() ([]byte, error) {
	*p.Called = true
	return []byte(`{"unexpected":"encoder reached"}`), nil
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
func (f *fakeBackend) seenTenants() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.tenants...)
}
func (f *fakeBackend) ListTests(_ context.Context, p *auth.Principal) (TestsResult, error) {
	f.rec("ListTests", p)
	if f.listTestsErr != nil {
		return TestsResult{}, f.listTestsErr
	}
	if f.listTestsResult != nil {
		return *f.listTestsResult, nil
	}
	return TestsResult{Tests: []TestSummary{}}, nil
}
func (f *fakeBackend) GetPath(_ context.Context, p *auth.Principal, target string) (PathResult, error) {
	f.rec("GetPath", p)
	return PathResult{Found: true, Target: target}, nil
}
func (f *fakeBackend) GetBGPEvents(_ context.Context, p *auth.Principal, _, _ string, _ int) (EventsResult, error) {
	f.rec("GetBGPEvents", p)
	return EventsResult{Events: []ai.Row{}}, nil
}
func (f *fakeBackend) QueryFlows(_ context.Context, p *auth.Principal, _, _, _ string, _ int) (EventsResult, error) {
	f.rec("QueryFlows", p)
	return EventsResult{Events: []ai.Row{}}, nil
}
func (f *fakeBackend) GetIncident(_ context.Context, p *auth.Principal, id string) (IncidentResult, error) {
	f.rec("GetIncident", p)
	return IncidentResult{ID: id}, nil
}
func (f *fakeBackend) CorrelateIncident(_ context.Context, p *auth.Principal, id string) (CorrelationResult, error) {
	f.rec("CorrelateIncident", p)
	return CorrelationResult{Incident: IncidentResult{ID: id}}, nil
}
func (f *fakeBackend) ExplainDegradation(_ context.Context, p *auth.Principal, q string, _ map[string]string) (ai.Answer, error) {
	f.rec("ExplainDegradation", p)
	return ai.Answer{RootCause: "x", Question: q}, nil
}

func (f *fakeBackend) ProposeRemediation(_ context.Context, p *auth.Principal, kind, title, _, _, _ string) (ProposalResult, error) {
	f.rec("ProposeRemediation", p)
	return ProposalResult{State: "proposed", Kind: kind, Title: title}, nil
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
	s := newTestServer(&fakeBackend{}, testGate())
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
	s := newTestServer(&fakeBackend{}, testGate())
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

func TestMCPABACDenyOverridesRBAC(t *testing.T) {
	fb := &fakeBackend{}
	denyContractorRead := auth.Policy{
		ID:         "tenant-a-deny",
		Effect:     auth.PolicyDeny,
		Permission: permTestRead,
		Subject:    map[string]string{"department": "contractor"},
		Enabled:    true,
	}
	s := newTestServer(fb, testGate(), WithPolicyLoader(func(_ context.Context, tenantID string) ([]auth.Policy, error) {
		if tenantID == "tenant-a" {
			return []auth.Policy{denyContractorRead}, nil
		}
		return nil, nil
	}))
	tenantA := principal("tenant-a", permTestRead)
	tenantA.Attributes = map[string]string{"department": "contractor"}
	tenantB := principal("tenant-b", permTestRead)
	tenantB.Attributes = map[string]string{"department": "contractor"}

	// Tenant A's ABAC deny hides both test.read tools despite the RBAC grant.
	tenantATools := listedToolNames(t, handle(t, s, tenantA, 40, "tools/list", nil))
	for _, denied := range []string{"list_tests", "get_path"} {
		if tenantATools[denied] {
			t.Fatalf("tenant A discovered ABAC-denied tool %q: %v", denied, tenantATools)
		}
	}

	// The same RBAC + subject attributes in tenant B are unaffected by tenant
	// A's policy, proving the loader is keyed by the principal's tenant.
	tenantBTools := listedToolNames(t, handle(t, s, tenantB, 41, "tools/list", nil))
	for _, allowed := range []string{"list_tests", "get_path"} {
		if !tenantBTools[allowed] {
			t.Fatalf("tenant B lost tool %q to tenant A's policy: %v", allowed, tenantBTools)
		}
	}

	resp := handle(t, s, tenantA, 42, "tools/call", map[string]any{"name": "list_tests"})
	if code, _ := errCode(resp); code != codeForbidden {
		t.Fatalf("tenant A ABAC-denied call: code = %d, want %d", code, codeForbidden)
	}
	if got := fb.seen(); len(got) != 0 {
		t.Fatalf("tenant A ABAC-denied call reached backend: %v", got)
	}

	if resultOf(t, handle(t, s, tenantB, 43, "tools/call", map[string]any{"name": "list_tests"}))["isError"] == true {
		t.Fatal("tenant B's policy-isolated call was denied")
	}
	if got := fb.seenTenants(); len(got) != 1 || got[0] != "tenant-b" {
		t.Fatalf("backend tenants = %v, want only tenant-b", got)
	}
}

func TestMCPABACPolicyLoadFailureFailsClosed(t *testing.T) {
	fb := &fakeBackend{}
	loads := 0
	var events []CallEvent
	s := newTestServer(fb, testGate(), WithPolicyLoader(func(context.Context, string) ([]auth.Policy, error) {
		loads++
		return nil, errors.New("policy store unavailable")
	}), WithCallAudit(func(_ context.Context, event CallEvent) error {
		events = append(events, event)
		return nil
	}))
	granted := principal("tenant-a", permTestRead)

	if code, _ := errCode(handle(t, s, granted, 44, "tools/list", nil)); code != codeUnavailable {
		t.Fatalf("tools/list policy-load failure: code = %d, want %d", code, codeUnavailable)
	}
	if code, _ := errCode(handle(t, s, granted, 45, "tools/call",
		map[string]any{"name": "list_tests"})); code != codeUnavailable {
		t.Fatalf("tools/call policy-load failure: code = %d, want %d", code, codeUnavailable)
	}
	if got := fb.seen(); len(got) != 0 {
		t.Fatalf("policy-load failure reached backend: %v", got)
	}
	if len(events) != 1 || events[0].Phase != CallPhaseTerminal || events[0].Allowed || events[0].Denial != "policy" {
		t.Fatalf("tools/call policy-load denial audit = %+v", events)
	}

	// RBAC still precedes ABAC: a caller with no matching RBAC grants gets an
	// empty catalog/forbidden call without consulting the policy store.
	ungranted := principal("tenant-a")
	if got := listedToolNames(t, handle(t, s, ungranted, 46, "tools/list", nil)); len(got) != 0 {
		t.Fatalf("RBAC-empty catalog = %v, want no tools", got)
	}
	if code, _ := errCode(handle(t, s, ungranted, 47, "tools/call",
		map[string]any{"name": "list_tests"})); code != codeForbidden {
		t.Fatalf("RBAC-denied call: code = %d, want %d", code, codeForbidden)
	}
	if loads != 2 {
		t.Fatalf("policy loader called %d times, want only the two RBAC-granted requests", loads)
	}
}

func listedToolNames(t *testing.T, resp map[string]any) map[string]bool {
	t.Helper()
	tools, ok := resultOf(t, resp)["tools"].([]any)
	if !ok {
		t.Fatalf("tools/list result has no tools array: %v", resp)
	}
	names := make(map[string]bool, len(tools))
	for _, raw := range tools {
		tool, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("invalid tool descriptor: %v", raw)
		}
		name, _ := tool["name"].(string)
		names[name] = true
	}
	return names
}

func TestToolsCallTenantScopedAndForbidden(t *testing.T) {
	fb := &fakeBackend{}
	s := newTestServer(fb, testGate())

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
	s2 := newTestServer(fb2, testGate())
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
		"tenant missing": {Permissions: map[string]bool{permTestRead: true}},
	} {
		t.Run(name, func(t *testing.T) {
			fb := &fakeBackend{}
			s := newTestServer(fb, testGate())
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
	s := newTestServer(fb, testGate())
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
	s := newTestServer(fb, testGate())

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
	s2 := newTestServer(fb2, testGate())
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
	s := newTestServer(&fakeBackend{}, testGate())
	if code, _ := errCode(handle(t, s, principal(""), 6, "tools/list", nil)); code != codeUnauthorized {
		t.Errorf("tenantless principal: code = %d, want %d", code, codeUnauthorized)
	}
}

func TestToolArgValidationIsError(t *testing.T) {
	s := newTestServer(&fakeBackend{}, testGate())
	// get_path with no target → an isError tool result (not a transport error).
	res := resultOf(t, handle(t, s, principal("t", permTestRead), 7, "tools/call",
		map[string]any{"name": "get_path", "arguments": map[string]any{}}))
	if res["isError"] != true {
		t.Errorf("missing required arg should yield an isError result, got %v", res)
	}
}

func TestRateLimit(t *testing.T) {
	fb := &fakeBackend{}
	s := newTestServer(fb, testGate(), WithRateLimit(1))
	p := principal("t", permTestRead)
	if _, isErr := errCode(handle(t, s, p, 8, "tools/call", map[string]any{"name": "list_tests"})); isErr {
		t.Fatal("first call should be allowed")
	}
	if code, _ := errCode(handle(t, s, p, 9, "tools/call", map[string]any{"name": "list_tests"})); code != codeRateLimited {
		t.Errorf("second call: code = %d, want %d (rate limited)", code, codeRateLimited)
	}
}

func TestMCPFairnessAuditRecordsTerminalDenial(t *testing.T) {
	backend := &fakeBackend{listTestsErr: fairness.ErrQueryConcurrency}
	var events []CallEvent
	server := newTestServer(backend, testGate(), WithCallAudit(func(_ context.Context, event CallEvent) error {
		events = append(events, event)
		return nil
	}))

	result := resultOf(t, handle(t, server, principal("tenant-a", permTestRead), 91, "tools/call",
		map[string]any{"name": "list_tests"}))
	if result["isError"] != true {
		t.Fatalf("fairness rejection must not return tool data: %v", result)
	}
	if len(events) != 2 {
		t.Fatalf("fairness-rejected call audit events = %+v, want admission plus terminal denial", events)
	}
	if events[0].Phase != CallPhaseAdmission || !events[0].Allowed ||
		events[1].Phase != CallPhaseTerminal || events[1].Allowed || events[1].Denial != "fairness_concurrency" {
		t.Fatalf("fairness-rejected call has ambiguous durable outcome: %+v", events)
	}
}

func TestParseError(t *testing.T) {
	s := newTestServer(&fakeBackend{}, testGate())
	var resp map[string]any
	_ = json.Unmarshal(s.Handle(context.Background(), principal("t"), []byte("{bad")), &resp)
	if code, _ := errCode(resp); code != codeParse {
		t.Errorf("malformed JSON: code = %d, want %d", code, codeParse)
	}
}

func TestToolResultEncodingExactLimitAndOnePast(t *testing.T) {
	// json.Encoder appends one newline. A JSON string adds two quote bytes, so
	// this payload makes the bounded writer accept exactly max bytes.
	exact := strings.Repeat("x", maxMCPToolResultBytes-3)
	got, err := marshalBoundedJSON(exact, maxMCPToolResultBytes, false)
	if err != nil {
		t.Fatalf("exact byte limit rejected: %v", err)
	}
	if len(got) != maxMCPToolResultBytes-1 {
		t.Fatalf("encoded exact-bound result = %d bytes after newline removal, want %d", len(got), maxMCPToolResultBytes-1)
	}

	onePast := strings.Repeat("x", maxMCPToolResultBytes-2)
	if _, err := marshalBoundedJSON(onePast, maxMCPToolResultBytes, false); !errors.Is(err, errToolResultTooLarge) {
		t.Fatalf("one-past byte limit error = %v, want %v", err, errToolResultTooLarge)
	}
}

func TestRPCResponseSourceBudgetRunsBeforeMarshal(t *testing.T) {
	called := false
	resp := resultResponse(nil, sourceBudgetMarshalProbe{
		Nodes:  make([]struct{}, maxMCPToolResultNodes+1),
		Called: &called,
	})
	out := marshal(resp)
	if called {
		t.Fatal("encoding/json ran before the outer RPC source budget rejected the response")
	}
	if len(out) > maxMCPToolResultBytes {
		t.Fatalf("fallback response = %d bytes, limit %d", len(out), maxMCPToolResultBytes)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("bounded fallback is not JSON: %v", err)
	}
	if code, ok := errCode(decoded); !ok || code != codeInternal {
		t.Fatalf("bounded fallback = %v, want internal error", decoded)
	}
}

func TestMCPBackendErrorsUseBoundedPublicMessage(t *testing.T) {
	const sentinel = "backend-schema-host-secret-sentinel"
	fb := &fakeBackend{listTestsErr: errors.New(strings.Repeat(sentinel, 256))}
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := newTestServer(fb, testGate(), WithLogger(discard))
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_tests","arguments":{}}}`)
	out := s.Handle(context.Background(), principal("tenant-a", permTestRead), raw)
	if len(out) > maxMCPToolResultBytes {
		t.Fatalf("backend-error response = %d bytes, limit %d", len(out), maxMCPToolResultBytes)
	}
	if bytes.Contains(out, []byte(sentinel)) {
		t.Fatalf("backend error reached the MCP wire: %s", out)
	}
	var resp struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("backend-error response is not JSON: %v", err)
	}
	content, _ := resp.Result["content"].([]any)
	if len(content) != 1 || content[0].(map[string]any)["text"] != "tool execution failed" {
		t.Fatalf("public backend error = %v, want fixed bounded message", resp.Result)
	}
}

func TestRPCRequestIDBoundsAcrossTransports(t *testing.T) {
	s := newTestServer(&fakeBackend{}, testGate())
	exactID := `"` + strings.Repeat("i", maxMCPRequestIDBytes-2) + `"`
	onePastID := `"` + strings.Repeat("i", maxMCPRequestIDBytes-1) + `"`
	request := func(id string) []byte {
		return []byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"ping"}`)
	}
	assert := func(t *testing.T, out []byte, wantID string, wantError bool) {
		t.Helper()
		if len(out) > maxMCPToolResultBytes {
			t.Fatalf("response = %d bytes, limit %d", len(out), maxMCPToolResultBytes)
		}
		var resp rpcResponse
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Fatalf("response is not JSON: %v", err)
		}
		if wantError {
			if resp.Error == nil || resp.Error.Code != codeInvalidRequest || len(resp.ID) != 0 {
				t.Fatalf("one-past ID response = %+v, want ID-less invalid request", resp)
			}
			return
		}
		if resp.Error != nil || string(resp.ID) != wantID {
			t.Fatalf("exact ID response = %+v, want echoed bounded ID", resp)
		}
	}
	transports := map[string]func(t *testing.T, raw []byte) []byte{
		"direct": func(_ *testing.T, raw []byte) []byte {
			return s.Handle(context.Background(), principal("tenant-a"), raw)
		},
		"http": func(t *testing.T, raw []byte) []byte {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(raw))
			req.Header.Set("Authorization", "Bearer token")
			rec := httptest.NewRecorder()
			s.HTTPHandler(fakeAuthn{p: principal("tenant-a")}).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("HTTP status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
			}
			return rec.Body.Bytes()
		},
		"stdio": func(t *testing.T, raw []byte) []byte {
			var out bytes.Buffer
			if err := s.ServeStdio(context.Background(), bytes.NewReader(append(raw, '\n')), &out, principal("tenant-a")); err != nil {
				t.Fatal(err)
			}
			return bytes.TrimSuffix(out.Bytes(), []byte{'\n'})
		},
	}
	for name, transport := range transports {
		t.Run(name+"/exact", func(t *testing.T) {
			assert(t, transport(t, request(exactID)), exactID, false)
		})
		t.Run(name+"/one-past", func(t *testing.T) {
			assert(t, transport(t, request(onePastID)), "", true)
		})
	}
}

func TestListTestsSerializedPayloadLimit(t *testing.T) {
	t.Run("source node budget runs before encoder", func(t *testing.T) {
		called := false
		probe := sourceBudgetMarshalProbe{
			Nodes:  make([]struct{}, maxMCPToolResultNodes+1),
			Called: &called,
		}
		if _, err := marshalBoundedJSON(probe, maxMCPToolResultBytes, false); !errors.Is(err, errToolResultTooLarge) {
			t.Fatalf("node-heavy source error = %v, want %v", err, errToolResultTooLarge)
		}
		if called {
			t.Fatal("encoding/json ran before the source-node budget rejected the value")
		}
	})

	t.Run("source byte budget", func(t *testing.T) {
		source := strings.Repeat("x", maxMCPToolResultBytes+1)
		if _, err := marshalBoundedJSON(source, maxMCPToolResultBytes, false); !errors.Is(err, errToolResultTooLarge) {
			t.Fatalf("byte-heavy source error = %v, want %v", err, errToolResultTooLarge)
		}
	})

	fb := &fakeBackend{listTestsResult: &TestsResult{
		Tests: []TestSummary{{Name: strings.Repeat("x", maxMCPToolResultBytes+1)}},
	}}
	s := newTestServer(fb, testGate())
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_tests","arguments":{}}}`)
	assertInternal := func(t *testing.T, payload []byte) {
		t.Helper()
		var resp map[string]any
		if err := json.Unmarshal(payload, &resp); err != nil {
			t.Fatalf("bounded response is not valid JSON: %v", err)
		}
		if code, ok := errCode(resp); !ok || code != codeInternal {
			t.Fatalf("oversized tool response = %v, want internal error", resp)
		}
	}

	t.Run("HTTP handler", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer token")
		rec := httptest.NewRecorder()
		s.HTTPHandler(fakeAuthn{p: principal("tenant-a", permTestRead)}).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("HTTP status = %d, want %d", rec.Code, http.StatusOK)
		}
		if rec.Body.Len() > maxMCPToolResultBytes {
			t.Fatalf("HTTP oversized-result response = %d bytes, limit %d", rec.Body.Len(), maxMCPToolResultBytes)
		}
		if bytes.HasSuffix(rec.Body.Bytes(), []byte{'\n'}) {
			t.Fatal("HTTP response unexpectedly contains stdio framing newline")
		}
		assertInternal(t, rec.Body.Bytes())
	})

	t.Run("stdio", func(t *testing.T) {
		var out bytes.Buffer
		in := bytes.NewReader(append(append([]byte(nil), raw...), '\n'))
		if err := s.ServeStdio(context.Background(), in, &out, principal("tenant-a", permTestRead)); err != nil {
			t.Fatal(err)
		}
		if out.Len() > maxMCPToolResultBytes+1 {
			t.Fatalf("stdio oversized-result response = %d bytes, framed limit %d", out.Len(), maxMCPToolResultBytes+1)
		}
		if !bytes.HasSuffix(out.Bytes(), []byte{'\n'}) {
			t.Fatal("stdio response is missing its one newline framing byte")
		}
		assertInternal(t, bytes.TrimSuffix(out.Bytes(), []byte{'\n'}))
	})
}

func TestServeStdioRoundTrip(t *testing.T) {
	s := newTestServer(&fakeBackend{}, testGate())
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
	s := newTestServer(&fakeBackend{}, testGate())
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
	s := newTestServer(&fakeBackend{}, testGate())
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
	s := newTestServer(&fakeBackend{}, testGate())
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
