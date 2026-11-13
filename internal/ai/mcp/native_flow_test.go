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
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

type nativeBackendProbe struct {
	result    NativeFlowQueryResult
	err       error
	csvResult NativeFlowCSVResult
	calls     int
	plan      flow.QueryPlan
	onQuery   func()
}

func (*nativeBackendProbe) FlowPlan(context.Context, *auth.Principal, NativeFlowQuestionInput) (NativeFlowQuestionResult, error) {
	return NativeFlowQuestionResult{}, errors.New("unexpected native operation")
}

func (b *nativeBackendProbe) FlowQuery(_ context.Context, _ *auth.Principal, p flow.QueryPlan) (NativeFlowQueryResult, error) {
	b.calls++
	if b.onQuery != nil {
		b.onQuery()
	}
	b.plan = p
	return b.result, b.err
}

func TestNativeMCPRefusalsGiveSafeActionableCodes(t *testing.T) {
	marker := "PRIVATE-DEPENDENCY-DETAIL"
	for _, tc := range []struct {
		err  error
		code string
	}{
		{apierror.Validation(marker).WithCode(string(apierror.CodeFlowQueryBudget)), "flow_query_budget_exceeded"},
		{apierror.Validation(marker).WithCode(string(apierror.CodeFlowQueryCoverage)), "flow_query_coverage_unavailable"},
		{apierror.Conflict(marker), "conflict"},
		{apierror.NotFound(marker), "not_found"},
		{apierror.Validation(marker), "validation"},
		{errors.New(marker), "tool execution failed"},
	} {
		server := nativeProbeServer(&nativeBackendProbe{err: tc.err}, nil)
		raw := server.Handle(t.Context(), nativePrincipal(), nativeRequest("flow_explorer_query", map[string]any{"plan": map[string]any{}}))
		if bytes.Contains(raw, []byte(marker)) || !bytes.Contains(raw, []byte(tc.code)) {
			t.Fatalf("native refusal omitted safe %s code or exposed dependency data", tc.code)
		}
	}
}
func (*nativeBackendProbe) FlowSchema(_ context.Context, _ *auth.Principal) (NativeFlowSchemaResult, error) {
	return NativeFlowSchemaResult{}, errors.New("unexpected native operation")
}
func (*nativeBackendProbe) FlowCompare(_ context.Context, _ *auth.Principal, _ NativeFlowCompareInput) (NativeFlowComparisonResult, error) {
	return NativeFlowComparisonResult{}, errors.New("unexpected native operation")
}
func (*nativeBackendProbe) FlowPage(_ context.Context, _ *auth.Principal, _ string) (NativeFlowQueryResult, error) {
	return NativeFlowQueryResult{}, errors.New("unexpected native operation")
}
func (*nativeBackendProbe) FlowComparisonPage(_ context.Context, _ *auth.Principal, _ string) (NativeFlowComparisonResult, error) {
	return NativeFlowComparisonResult{}, errors.New("unexpected native operation")
}
func (b *nativeBackendProbe) FlowCSV(_ context.Context, _ *auth.Principal, _ NativeFlowCSVInput) (NativeFlowCSVResult, error) {
	return b.csvResult, nil
}

func TestNativeMCPCSVWholeCellsTraverseMandatoryRedaction(t *testing.T) {
	b := &nativeBackendProbe{csvResult: NativeFlowCSVResult{Columns: []string{"record_type", "label", "bytes:total"}, Records: [][]string{{"detail", "password=local-fixture-only", "9007199254740993"}, {"detail", "雪,\"quoted\"\nline", "9007199254740994"}}, TotalRecords: 2}}
	server := nativeProbeServer(b, nil)
	raw := server.Handle(t.Context(), nativePrincipal(), nativeRequest("flow_explorer_csv", NativeFlowCSVInput{SnapshotID: "owned-result"}))
	if bytes.Contains(raw, []byte("local-fixture-only")) || !bytes.Contains(raw, []byte("9007199254740993")) || !bytes.Contains(raw, []byte("雪")) {
		t.Fatal("CSV cell escaped redaction or lost exact non-secret data")
	}
}
func (*nativeBackendProbe) FlowFilters(_ context.Context, _ *auth.Principal, _ string, _ int) (NativeFlowFilterPage, error) {
	return NativeFlowFilterPage{}, errors.New("unexpected native operation")
}
func (*nativeBackendProbe) FlowFilter(_ context.Context, _ *auth.Principal, _ string) (NativeFlowFilter, error) {
	return NativeFlowFilter{}, errors.New("unexpected native operation")
}
func (*nativeBackendProbe) SaveFlowFilter(_ context.Context, _ *auth.Principal, _ NativeFlowFilterInput) (NativeFlowFilter, error) {
	return NativeFlowFilter{}, errors.New("unexpected native operation")
}
func (*nativeBackendProbe) DeleteFlowFilter(_ context.Context, _ *auth.Principal, _ string, _ string) (NativeFlowMutationResult, error) {
	return NativeFlowMutationResult{}, errors.New("unexpected native operation")
}
func (*nativeBackendProbe) FlowViews(_ context.Context, _ *auth.Principal, _ NativeFlowViewListInput) (NativeFlowViewPage, error) {
	return NativeFlowViewPage{}, errors.New("unexpected native operation")
}
func (*nativeBackendProbe) FlowView(_ context.Context, _ *auth.Principal, _ string) (NativeFlowView, error) {
	return NativeFlowView{}, errors.New("unexpected native operation")
}
func (*nativeBackendProbe) SaveFlowView(_ context.Context, _ *auth.Principal, _ flow.SaveQueryView) (NativeFlowView, error) {
	return NativeFlowView{}, errors.New("unexpected native operation")
}
func (*nativeBackendProbe) DeleteFlowView(_ context.Context, _ *auth.Principal, _ string, _ string) (NativeFlowMutationResult, error) {
	return NativeFlowMutationResult{}, errors.New("unexpected native operation")
}
func (*nativeBackendProbe) FavoriteFlowView(_ context.Context, _ *auth.Principal, _ string, _ bool) (NativeFlowMutationResult, error) {
	return NativeFlowMutationResult{}, errors.New("unexpected native operation")
}
func (*nativeBackendProbe) RunFlowView(_ context.Context, _ *auth.Principal, _ string) (NativeFlowExecution, error) {
	return NativeFlowExecution{}, errors.New("unexpected native operation")
}

func nativeProbeServer(b NativeFlowBackend, admit NativeFlowAdmission) *Server {
	schemas := NativeFlowSchemas{}
	for _, tool := range buildNativeFlowTools(b, nil) {
		schemas[tool.Name] = json.RawMessage(`{"type":"object"}`)
	}
	return newTestServer(&fakeBackend{}, testGate(), WithNativeFlowBackend(b, schemas, admit))
}
func nativePrincipal() *auth.Principal {
	return &auth.Principal{TenantID: "tenant-native", UserID: "reader", Permissions: map[string]bool{"ai.query": true, "flow.read": true}}
}
func nativeRequest(name string, args any) []byte {
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	return raw
}

func TestNativeMCPFullPageSurvivesBothWireCopiesAndFinalMarshaling(t *testing.T) {
	b := &nativeBackendProbe{}
	b.result.Flow.Rows = make([]NativeFlowRow, 5000)
	for i := range b.result.Flow.Rows {
		row := &b.result.Flow.Rows[i]
		for _, field := range []string{"src_addr", "dst_addr", "src_port", "dst_port", "protocol", "exporter", "in_if", "out_if"} {
			row.Group = append(row.Group, NativeFlowDimension{Field: field, Value: strings.Repeat("diagnostic-value-", 8)})
		}
		row.Metrics = []NativeFlowValue{{Metric: "bytes:total", Value: "9007199254740993", Defined: true}}
	}
	held, releases := false, 0
	server := nativeProbeServer(b, func(_ context.Context, _ *auth.Principal) (func(), error) {
		held = true
		return func() { held = false; releases++ }, nil
	})
	if _, err := server.redactedToolResult("tenant-native", b.result, false); err == nil {
		t.Fatal("legacy result budget was loosened")
	}
	request := nativeRequest("flow_explorer_query", map[string]any{"plan": map[string]any{}})
	var req rpcRequest
	if err := json.Unmarshal(request, &req); err != nil {
		t.Fatal(err)
	}
	response := server.dispatch(t.Context(), nativePrincipal(), req)
	if !held || response.finalize == nil {
		t.Fatal("query fairness released before final RPC encoding")
	}
	raw := marshal(response)
	if !held || len(raw) <= 1<<20 {
		t.Fatal("native page was capped or fairness released while encoding")
	}
	response.finalize()
	if held || releases != 1 {
		t.Fatal("native fairness did not release exactly once")
	}
	var decoded struct {
		Error  *rpcError `json:"error"`
		Result struct {
			Structured NativeFlowQueryResult `json:"structuredContent"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &decoded) != nil || decoded.Error != nil || len(decoded.Result.Structured.Flow.Rows) != 5000 || decoded.Result.Structured.Flow.Rows[4999].Metrics[0].Value != "9007199254740993" {
		t.Fatal("complete native page or exact values lost at final wire")
	}
	_ = server.Handle(t.Context(), nativePrincipal(), request)
	if held || releases != 2 {
		t.Fatal("Handle did not finalize native admission")
	}
}

func TestNativeMCPDiscoveryAndInvocationRequireEveryPermission(t *testing.T) {
	b := &nativeBackendProbe{}
	server := nativeProbeServer(b, nil)
	for _, permissions := range []map[string]bool{{"flow.read": true}, {"ai.query": true}, {}} {
		p := nativePrincipal()
		p.Permissions = permissions
		listed, err := server.listTools(t.Context(), p)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(listed)
		if bytes.Contains(encoded, []byte("flow_explorer_query")) {
			t.Fatal("native discovery ignored a required permission")
		}
		before := b.calls
		reply := server.Handle(t.Context(), p, nativeRequest("flow_explorer_query", map[string]any{"plan": map[string]any{}}))
		if !bytes.Contains(reply, []byte(`"code":-32002`)) || b.calls != before {
			t.Fatal("native invocation ignored a required permission")
		}
	}
	p := nativePrincipal()
	p.UserID = ""
	before := b.calls
	reply := server.Handle(t.Context(), p, nativeRequest("flow_explorer_query", map[string]any{"plan": map[string]any{}}))
	if !bytes.Contains(reply, []byte(`"code":-32001`)) || b.calls != before {
		t.Fatal("native invocation adopted missing subject identity")
	}
	server.policyLoader = func(context.Context, string) ([]auth.Policy, error) {
		return []auth.Policy{{Effect: auth.PolicyDeny, Permission: "ai.query", Enabled: true}}, nil
	}
	listed, err := server.listTools(t.Context(), nativePrincipal())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(listed)
	if bytes.Contains(encoded, []byte("flow_explorer_query")) {
		t.Fatal("native discovery ignored secondary-permission ABAC")
	}
}

func TestNativeMCPArgumentsRejectAmbiguityAndAuthorityFields(t *testing.T) {
	b := &nativeBackendProbe{}
	server := nativeProbeServer(b, nil)
	tool := server.tools["flow_explorer_query"]
	for _, raw := range []string{
		`{"plan":{"tenant_id":"foreign"}}`, `{"plan":{},"Plan":{}}`, `{"plan":{"view":"table","view":"line"}}`,
		`{"plan":{"Group_By":["protocol"]}}`, `{"plan":{"group_by":["protocol"]},"budget":100}`, `{"plan":{}} {}`,
		`{"plan":{"filter":{"conditions":[{"field":"protocol","op":"eq","op":"regex","values":["x"]}]}}}`,
	} {
		before := b.calls
		if _, err := tool.Invoke(t.Context(), nativePrincipal(), json.RawMessage(raw)); err == nil || b.calls != before {
			t.Fatal("ambiguous/undeclared native input reached backend", raw)
		}
	}
	before := b.calls
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"flow_explorer_query","arguments":{"plan":{}}},"params":{"name":"flow_explorer_query","arguments":{"plan":{}}}}`)
	reply := server.Handle(t.Context(), nativePrincipal(), raw)
	if !bytes.Contains(reply, []byte(`"code":-32602`)) || b.calls != before {
		t.Fatal("duplicate native RPC envelope reached backend")
	}
	// Native byte admission may inspect only the registered name, but it
	// never grants dispatch authority to an ambiguous oversized envelope.
	socket := httptest.NewTLSServer(server.HTTPHandler(nativeTestAuthenticator{p: nativePrincipal()}))
	defer socket.Close()
	large := append(bytes.Repeat([]byte{' '}, 1<<20), raw...)
	for _, version := range []string{"", legacyProtocolVersion} {
		response := legacyTLSCall(t, socket, large, "owned", version)
		body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(body, []byte(`"error"`)) || b.calls != before {
			t.Fatal("native byte admission bypassed strict envelope validation", version)
		}
	}
}

type nativeTestAuthenticator struct{ p *auth.Principal }

func (a nativeTestAuthenticator) Authenticate(context.Context, string) (*auth.Principal, error) {
	return a.p, nil
}
func TestNativeMCPLegalLargeGrammarWorksOnHTTPAndStdio(t *testing.T) {
	b := &nativeBackendProbe{}
	server := nativeProbeServer(b, nil)
	filter := &flow.QueryFilterGroup{Groups: make([]flow.QueryFilterGroup, 4)}
	for i := range filter.Groups {
		for j := 0; j < 250; j++ {
			filter.Groups[i].Conditions = append(filter.Groups[i].Conditions, flow.QueryPredicate{Field: "protocol", Op: flow.QueryEqual, Values: []string{strings.Repeat("a", 1200)}})
		}
	}
	plan, err := flow.NormalizeQueryPlan(flow.QueryPlan{From: time.Now().Add(-401 * 24 * time.Hour), To: time.Now(), GroupBy: []string{"protocol"}, Filter: filter}, time.Now())
	if err != nil {
		t.Fatal("fixture is outside the public grammar", err)
	}
	raw := nativeRequest("flow_explorer_query", nativeFlowQueryArgs{Plan: plan})
	if len(raw) <= 1<<20 || len(raw) >= nativeFlowRequestBytes {
		t.Fatal("fixture does not exercise the large legal grammar")
	}
	request := httptest.NewRequest(http.MethodPost, "https://mcp.invalid/", bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer diagnostic-token")
	recorder := httptest.NewRecorder()
	server.HTTPHandler(nativeTestAuthenticator{nativePrincipal()}).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || b.calls != 1 {
		t.Fatal("HTTP reduced native grammar reach", recorder.Code)
	}
	var output bytes.Buffer
	if err := server.ServeStdio(t.Context(), strings.NewReader(string(raw)+"\n"), &output, nativePrincipal()); err != nil || b.calls != 2 {
		t.Fatal("stdio reduced native grammar reach", err)
	}
	if len(b.plan.Filter.Groups) != 4 || len(b.plan.Filter.Groups[3].Conditions) != 250 {
		t.Fatal("native parser truncated conditions")
	}
	// The extended native allowance does not extend the legacy HTTP surface.
	legacy := bytes.Replace(raw, []byte("flow_explorer_query"), []byte("query_flows"), 1)
	request = httptest.NewRequest(http.MethodPost, "https://mcp.invalid/", bytes.NewReader(legacy))
	request.Header.Set("Authorization", "Bearer diagnostic-token")
	recorder = httptest.NewRecorder()
	server.HTTPHandler(nativeTestAuthenticator{nativePrincipal()}).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge || b.calls != 2 {
		t.Fatal("legacy HTTP input budget changed")
	}
}

func TestNativeMCPDeclaredResultsContainNoUncheckedMapsRecursively(t *testing.T) {
	visited := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		if visited[typ] {
			return
		}
		visited[typ] = true
		switch typ.Kind() {
		case reflect.Map, reflect.Interface:
			t.Errorf("native result contains undeclared dynamic type %s", typ)
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(typ.Elem())
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.PkgPath != "" || field.Tag.Get("json") == "-" {
					continue
				}
				walk(field.Type)
			}
		}
	}
	backend := reflect.TypeOf((*NativeFlowBackend)(nil)).Elem()
	for i := 0; i < backend.NumMethod(); i++ {
		walk(backend.Method(i).Type.Out(0))
	}
}

func TestNativeMCPCancellationDoesNotPublishPreparedData(t *testing.T) {
	for _, stage := range []string{"backend", "egress-audit", "terminal-audit"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			b := &nativeBackendProbe{result: NativeFlowQueryResult{Flow: NativeFlowResult{Rows: []NativeFlowRow{{Group: []NativeFlowDimension{{Field: "protocol", Value: "canceled-result-data"}}, Metrics: []NativeFlowValue{{Metric: "bytes:total", Value: "9007199254740993", Defined: true}}}}}}}
			if stage == "backend" {
				b.onQuery = cancel
			}
			releases := 0
			server := nativeProbeServer(b, func(context.Context, *auth.Principal) (func(), error) { return func() { releases++ }, nil })
			if stage == "egress-audit" {
				server.gate = ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil }, func(context.Context, ai.EgressEvent) error { cancel(); return nil }, ai.RedactionPolicy{})
			}
			if stage == "terminal-audit" {
				server.audit = func(_ context.Context, event CallEvent) error {
					if event.Phase == CallPhaseTerminal && event.Allowed {
						cancel()
					}
					return nil
				}
			}
			raw := server.Handle(ctx, nativePrincipal(), nativeRequest("flow_explorer_query", map[string]any{"plan": map[string]any{}}))
			if bytes.Contains(raw, []byte("canceled-result-data")) || !bytes.Contains(raw, []byte(`"error"`)) {
				t.Fatal("canceled prepared native data crossed final wire boundary")
			}
			if releases != 1 {
				t.Fatal("canceled native query did not release admission")
			}
		})
	}
}
