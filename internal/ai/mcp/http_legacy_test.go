// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

type protocolAuthFunc func(context.Context, string) (*auth.Principal, error)

func (f protocolAuthFunc) Authenticate(ctx context.Context, bearer string) (*auth.Principal, error) {
	return f(ctx, bearer)
}

func legacyTLSCall(t *testing.T, socket *httptest.Server, raw []byte, bearer, version string) *http.Response {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+bearer)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	if version != "" {
		r.Header.Set("MCP-Protocol-Version", version)
	}
	response, err := socket.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	return response
}

func legacyBody(t *testing.T, response *http.Response) []byte {
	t.Helper()
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func legacyQuery(id any, token any) []byte {
	return legacy2025Request("tools/call", id, map[string]any{"name": "flow_explorer_query", "arguments": map[string]any{"plan": map[string]any{}}, "_meta": map[string]any{"progressToken": token}})
}

func TestLegacy2025HTTPInitializeNotificationsAndHeaders(t *testing.T) {
	s := nativeProbeServer(&nativeBackendProbe{}, nil)
	socket := httptest.NewTLSServer(s.HTTPHandler(fakeAuthn{p: nativePrincipal()}))
	defer socket.Close()
	response := legacyTLSCall(t, socket, legacy2025Initialize(), "owned", "")
	defer response.Body.Close()
	raw := legacyBody(t, response)
	if response.StatusCode != 200 || response.Header.Get("MCP-Session-Id") != "" || !bytes.Contains(raw, []byte(`"protocolVersion":"2025-11-25"`)) || bytes.Contains(raw, []byte("resultType")) {
		t.Fatal("legacy HTTP negotiation created session authority or wrong shape")
	}
	for _, notification := range [][]byte{[]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), stdioCancelFrame(json.RawMessage("999")), []byte(`{"jsonrpc":"2.0","method":"notifications/ignored"}`)} {
		response := legacyTLSCall(t, socket, notification, "owned", legacyProtocolVersion)
		defer response.Body.Close()
		if raw := legacyBody(t, response); response.StatusCode != 202 || len(raw) != 0 {
			t.Fatal("valid/unknown legacy notification was not accepted without a body")
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(http.Header)
	}{
		{"missing-accept", func(h http.Header) { h.Del("Accept") }},
		{"wrong-content", func(h http.Header) { h.Set("Content-Type", "text/plain") }},
		{"duplicate-version", func(h http.Header) { h.Add("MCP-Protocol-Version", legacyProtocolVersion) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://localhost/mcp", bytes.NewReader(legacy2025Request("tools/list", 2, map[string]any{})))
			r.Header.Set("Authorization", "Bearer owned")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json, text/event-stream")
			r.Header.Set("MCP-Protocol-Version", legacyProtocolVersion)
			tc.mutate(r.Header)
			w := httptest.NewRecorder()
			s.HTTPHandler(fakeAuthn{p: nativePrincipal()}).ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatal("legacy HTTP invalid headers accepted", w.Code)
			}
		})
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		r, _ := http.NewRequestWithContext(t.Context(), method, socket.URL, nil)
		r.Header.Set("Authorization", "Bearer owned")
		response, err := socket.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != 405 || response.Header.Get("Allow") != http.MethodPost {
			t.Fatal("stateless legacy endpoint advertised unsupported stream/session operations")
		}
	}
}

func TestLegacy2025HTTPProgressEndsWithLegacyResult(t *testing.T) {
	b := &nativeBackendProbe{}
	b.result.Flow.Rows = []NativeFlowRow{{Group: []NativeFlowDimension{{Field: "protocol", Value: "owned-value"}}}}
	socket := httptest.NewTLSServer(nativeProbeServer(b, nil).HTTPHandler(fakeAuthn{p: nativePrincipal()}))
	defer socket.Close()
	response := legacyTLSCall(t, socket, legacyQuery(2, "owned-legacy-progress"), "owned", legacyProtocolVersion)
	defer response.Body.Close()
	raw := legacyBody(t, response)
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "text/event-stream" || bytes.Contains(raw, []byte("resultType")) {
		t.Fatal("legacy HTTP progress used modern result framing")
	}
	var frames [][]byte
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		if bytes.HasPrefix(line, []byte("data: ")) {
			frames = append(frames, bytes.TrimPrefix(line, []byte("data: ")))
		}
	}
	if len(frames) != 3 || !bytes.Contains(frames[0], []byte(`"progress":0`)) || !bytes.Contains(frames[1], []byte(`"progress":1`)) || bytes.Contains(frames[0], []byte("owned-value")) || !bytes.Contains(frames[2], []byte("owned-value")) {
		t.Fatal("legacy progress lost stages, privacy or complete result")
	}
}

type legacyBlockingBackend struct {
	*nativeBackendProbe
	started chan context.Context
	ended   chan struct{}
}

func (b *legacyBlockingBackend) FlowQuery(ctx context.Context, _ *auth.Principal, _ flow.QueryPlan) (NativeFlowQueryResult, error) {
	b.started <- ctx
	<-ctx.Done()
	close(b.ended)
	return NativeFlowQueryResult{}, ctx.Err()
}

func TestLegacy2025HTTPDisconnectKeepsWorkUntilScopedCancel(t *testing.T) {
	b := &legacyBlockingBackend{nativeBackendProbe: &nativeBackendProbe{}, started: make(chan context.Context, 1), ended: make(chan struct{})}
	released := make(chan struct{}, 1)
	s := nativeProbeServer(b, func(context.Context, *auth.Principal) (func(), error) { return func() { released <- struct{}{} }, nil })
	original := make(chan context.Context, 1)
	authn := protocolAuthFunc(func(_ context.Context, bearer string) (*auth.Principal, error) {
		p := nativePrincipal()
		switch bearer {
		case "same-owner-other-token":
		case "other-user":
			p.UserID = "sibling-user"
		case "other-tenant":
			p.TenantID = "sibling-tenant"
		}
		return p, nil
	})
	base := s.HTTPHandler(authn)
	socket := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case original <- r.Context():
		default:
		}
		base.ServeHTTP(w, r)
	}))
	defer socket.Close()
	defer s.legacyHTTP.cancelCredential("owned")
	response := legacyTLSCall(t, socket, legacyQuery(2, "owned-disconnect"), "owned", legacyProtocolVersion)
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if line, err := reader.ReadString('\n'); err != nil || !strings.Contains(line, "notifications/progress") {
		t.Fatal("query did not produce its admitted progress")
	}
	var sourceCtx context.Context
	select {
	case sourceCtx = <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("legacy source did not start")
	}
	requestCtx := <-original
	_ = response.Body.Close()
	select {
	case <-requestCtx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("fixture did not deliver actual HTTP disconnect")
	}
	if sourceCtx.Err() != nil {
		t.Fatal("legacy disconnect was misinterpreted as cancellation")
	}
	for _, token := range []string{"same-owner-other-token", "other-user", "other-tenant"} {
		response := legacyTLSCall(t, socket, stdioCancelFrame(json.RawMessage("2")), token, legacyProtocolVersion)
		defer response.Body.Close()
		if response.StatusCode != 202 || len(legacyBody(t, response)) != 0 || sourceCtx.Err() != nil {
			t.Fatal("foreign credential/owner/tenant canceled the active source")
		}
	}
	response = legacyTLSCall(t, socket, stdioCancelFrame(json.RawMessage("20e-1")), "owned", legacyProtocolVersion)
	defer response.Body.Close()
	if response.StatusCode != 202 || len(legacyBody(t, response)) != 0 {
		t.Fatal("authenticated cancel was not accepted")
	}
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("legacy cancellation retained admission")
	}
}

type legacyAuthorityBackend struct {
	*nativeBackendProbe
	changed *atomic.Bool
}

func (b *legacyAuthorityBackend) FlowQuery(ctx context.Context, p *auth.Principal, plan flow.QueryPlan) (NativeFlowQueryResult, error) {
	b.changed.Store(true)
	return b.nativeBackendProbe.FlowQuery(ctx, p, plan)
}

func TestLegacy2025HTTPChangedAuthorityRefusesBeforeEgressSuccess(t *testing.T) {
	for _, change := range []string{"revoked", "tenant", "user", "permissions", "attributes", "mfa", "abac", "abac-unavailable"} {
		t.Run(change, func(t *testing.T) {
			var changed atomic.Bool
			b := &legacyAuthorityBackend{nativeBackendProbe: &nativeBackendProbe{}, changed: &changed}
			b.result.Flow.Rows = []NativeFlowRow{{Group: []NativeFlowDimension{{Field: "protocol", Value: "private-row"}}}}
			s := nativeProbeServer(b, nil)
			WithPolicyLoader(func(context.Context, string) ([]auth.Policy, error) {
				if changed.Load() && change == "abac-unavailable" {
					return nil, errors.New("private policy store detail")
				}
				if changed.Load() && change == "abac" {
					return []auth.Policy{{Name: "joined-field-denial", Enabled: true, Effect: auth.PolicyDeny, Permission: "device.read"}}, nil
				}
				return nil, nil
			})(s)
			var successes atomic.Int32
			s.gate = ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil }, func(context.Context, ai.EgressEvent) error { successes.Add(1); return nil }, ai.RedactionPolicy{})
			var terminal atomic.Pointer[CallEvent]
			WithCallAudit(func(_ context.Context, event CallEvent) error {
				if event.Phase == CallPhaseTerminal {
					terminal.Store(&event)
				}
				return nil
			})(s)
			authn := protocolAuthFunc(func(context.Context, string) (*auth.Principal, error) {
				p := nativePrincipal()
				if changed.Load() {
					switch change {
					case "revoked":
						return nil, errors.New("private auth error")
					case "tenant":
						p.TenantID = "sibling"
					case "user":
						p.UserID = "sibling"
					case "permissions":
						p.Permissions = nil
					case "attributes":
						p.Attributes = map[string]string{"changed": "value"}
					case "mfa":
						p.MFASatisfied = !p.MFASatisfied
					}
				}
				return p, nil
			})
			socket := httptest.NewTLSServer(s.HTTPHandler(authn))
			defer socket.Close()
			response := legacyTLSCall(t, socket, legacyQuery(2, "owned-change"), "owned", legacyProtocolVersion)
			defer response.Body.Close()
			raw := legacyBody(t, response)
			event := terminal.Load()
			if bytes.Contains(raw, []byte("private-row")) || bytes.Contains(raw, []byte("private auth")) || bytes.Contains(raw, []byte("private policy")) || !bytes.Contains(raw, []byte(`"code":-33002`)) || successes.Load() != 0 || event == nil || event.Allowed || event.Denial != "authorization_changed" {
				t.Fatal("changed publication authority produced data or success receipt")
			}
		})
	}
}

func TestLegacy2025HTTPDeadlineAndActiveCostAreBounded(t *testing.T) {
	t.Run("listener-write-budget", func(t *testing.T) {
		for _, version := range []string{modernProtocolVersion, legacyProtocolVersion} {
			t.Run(version, func(t *testing.T) {
				b := &nativeBackendProbe{onQuery: func() { time.Sleep(250 * time.Millisecond) }}
				s := nativeProbeServer(b, nil)
				WithHTTPWorkBudget(HTTPWorkBudget{Timeout: 5 * time.Second, ActiveRequests: 2})(s)
				socket := httptest.NewUnstartedServer(s.HTTPHandler(fakeAuthn{p: nativePrincipal()}))
				socket.Config.WriteTimeout = 100 * time.Millisecond
				socket.StartTLS()
				defer socket.Close()
				params := map[string]any{"name": "flow_explorer_query", "arguments": map[string]any{"plan": map[string]any{}}}
				raw := modernRequest("tools/call", params)
				if version == legacyProtocolVersion {
					raw = legacyQuery(2, "write-budget")
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL, bytes.NewReader(raw))
				if err != nil {
					t.Fatal(err)
				}
				for key, value := range map[string]string{"Authorization": "Bearer owned", "Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": version, "Mcp-Method": "tools/call", "Mcp-Name": "flow_explorer_query"} {
					req.Header.Set(key, value)
				}
				response, err := socket.Client().Do(req)
				if err != nil {
					t.Fatal("listener cut off admitted native work", err)
				}
				body := legacyBody(t, response)
				if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"structuredContent"`)) || bytes.Contains(body, []byte(`"error"`)) || b.calls != 1 {
					t.Fatal("listener deadline lost the complete admitted native result", response.StatusCode)
				}
			})
		}
	})
	t.Run("larger-operator-profile", func(t *testing.T) {
		s := nativeProbeServer(&nativeBackendProbe{}, nil)
		WithHTTPWorkBudget(HTTPWorkBudget{Timeout: 25 * time.Hour, ActiveRequests: 1000001})(s)
		socket := httptest.NewTLSServer(s.HTTPHandler(fakeAuthn{p: nativePrincipal()}))
		defer socket.Close()
		response := legacyTLSCall(t, socket, legacy2025Request("ping", 2, map[string]any{}), "owned", legacyProtocolVersion)
		defer response.Body.Close()
		if raw := legacyBody(t, response); response.StatusCode != 200 || rpcErrorCode(raw) != 0 {
			t.Fatal("finite operator HTTP capacity rejected by a fixed maximum")
		}
	})
	t.Run("deadline", func(t *testing.T) {
		b := &legacyBlockingBackend{nativeBackendProbe: &nativeBackendProbe{}, started: make(chan context.Context, 1), ended: make(chan struct{})}
		released := make(chan struct{}, 1)
		s := nativeProbeServer(b, func(context.Context, *auth.Principal) (func(), error) { return func() { released <- struct{}{} }, nil })
		WithHTTPWorkBudget(HTTPWorkBudget{Timeout: 100 * time.Millisecond, ActiveRequests: 2})(s)
		socket := httptest.NewTLSServer(s.HTTPHandler(fakeAuthn{p: nativePrincipal()}))
		defer socket.Close()
		defer s.legacyHTTP.cancelCredential("owned")
		response := legacyTLSCall(t, socket, legacyQuery(2, "owned-timeout"), "owned", legacyProtocolVersion)
		defer response.Body.Close()
		raw := legacyBody(t, response)
		if bytes.Contains(raw, []byte(`"result"`)) {
			t.Fatal("expired legacy work produced a result")
		}
		select {
		case <-released:
		case <-time.After(5 * time.Second):
			t.Fatal("work deadline did not release source admission")
		}
		s.legacyHTTP.mu.Lock()
		defer s.legacyHTTP.mu.Unlock()
		if len(s.legacyHTTP.active) != 0 || len(s.legacyHTTP.tokens) != 0 {
			t.Fatal("expired legacy request retained registry claims")
		}
	})
	t.Run("active-and-aliases", func(t *testing.T) {
		b := &legacyBlockingBackend{nativeBackendProbe: &nativeBackendProbe{}, started: make(chan context.Context, 1), ended: make(chan struct{})}
		s := nativeProbeServer(b, nil)
		WithHTTPWorkBudget(HTTPWorkBudget{Timeout: time.Minute, ActiveRequests: 1})(s)
		socket := httptest.NewTLSServer(s.HTTPHandler(fakeAuthn{p: nativePrincipal()}))
		defer socket.Close()
		defer s.legacyHTTP.cancelCredential("owned")
		first := legacyTLSCall(t, socket, legacyQuery(json.Number("2.0"), json.Number("100e-2")), "owned", legacyProtocolVersion)
		defer first.Body.Close()
		select {
		case <-b.started:
		case <-time.After(5 * time.Second):
			t.Fatal("source did not start")
		}
		for _, tc := range []struct {
			id, token any
			status    int
		}{{2, "different", 400}, {3, 1, 400}, {4, "different", 429}} {
			response := legacyTLSCall(t, socket, legacyQuery(tc.id, tc.token), "owned", legacyProtocolVersion)
			defer response.Body.Close()
			raw := legacyBody(t, response)
			if response.StatusCode != tc.status || !bytes.Contains(raw, []byte(`"error"`)) || (tc.status == 429 && response.Header.Get("Retry-After") == "") {
				t.Fatal("duplicate request/progress or active cost escaped refusal", response.StatusCode)
			}
		}
		response := legacyTLSCall(t, socket, stdioCancelFrame(json.RawMessage("2")), "owned", legacyProtocolVersion)
		defer response.Body.Close()
		_ = legacyBody(t, response)
		_ = legacyBody(t, first) // completed handler releases all live-work claims
		for range 8 {
			response := legacyTLSCall(t, socket, legacy2025Request("ping", 2, map[string]any{}), "owned", legacyProtocolVersion)
			defer response.Body.Close()
			if raw := legacyBody(t, response); response.StatusCode != 200 || rpcErrorCode(raw) != 0 {
				t.Fatal("completed legacy HTTP request ID could not be reused")
			}
		}
	})
}

func TestLegacy2025HTTPRevokedCredentialCancelsOnlyItsAdmittedWork(t *testing.T) {
	b := &legacyBlockingBackend{nativeBackendProbe: &nativeBackendProbe{}, started: make(chan context.Context, 1), ended: make(chan struct{})}
	s := nativeProbeServer(b, nil)
	var revoked atomic.Bool
	authn := protocolAuthFunc(func(context.Context, string) (*auth.Principal, error) {
		if revoked.Load() {
			return nil, errors.New("private revocation detail")
		}
		return nativePrincipal(), nil
	})
	socket := httptest.NewTLSServer(s.HTTPHandler(authn))
	defer socket.Close()
	defer s.legacyHTTP.cancelCredential("owned")
	first := legacyTLSCall(t, socket, legacyQuery(2, "owned-revoked"), "owned", legacyProtocolVersion)
	defer first.Body.Close()
	select {
	case <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("source did not start")
	}
	revoked.Store(true)
	response := legacyTLSCall(t, socket, legacy2025Request("ping", 3, map[string]any{}), "owned", legacyProtocolVersion)
	defer response.Body.Close()
	if raw := legacyBody(t, response); response.StatusCode != http.StatusUnauthorized || bytes.Contains(raw, []byte("private revocation")) {
		t.Fatal("revoked credential was accepted or exposed private error")
	}
	select {
	case <-b.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("invalid credential frame retained its earlier admitted work")
	}
	_ = legacyBody(t, first)
}

func TestPublicationAuthorityGrantSetsIgnoreOrderButRefuseChange(t *testing.T) {
	a := nativePrincipal()
	a.PermissionGrants = []auth.PermissionGrant{{Permission: "flow.read", ScopeType: auth.ScopeProject, ScopeID: "owned-a"}, {Permission: "flow.read", ScopeType: auth.ScopeProject, ScopeID: "owned-b"}}
	b := principalSnapshot(a)
	b.PermissionGrants = []auth.PermissionGrant{a.PermissionGrants[1], a.PermissionGrants[0], a.PermissionGrants[0]}
	if !sameAuthority(a, b) {
		t.Fatal("grant ordering/duplicates changed authority")
	}
	b.PermissionGrants[0].ScopeID = "sibling"
	if sameAuthority(a, b) {
		t.Fatal("different resource scope retained publication authority")
	}
}

func TestLegacy2025HTTPInitializeCannotBeCanceled(t *testing.T) {
	p := nativePrincipal()
	req, failure := decodeLegacy2025RPC(legacy2025Initialize())
	if failure != nil {
		t.Fatal("fixture initialize invalid")
	}
	registry := &legacyHTTPRegistry{active: map[legacyHTTPKey]*legacyHTTPJob{}}
	job, failure := registry.begin(t.Context(), p, "owned", req, DefaultHTTPWorkBudget())
	if failure != nil {
		t.Fatal("fixture initialization not admitted")
	}
	defer job.finish()
	key, _ := requestIDKey(req.ID)
	registry.cancelRequest(p, "owned", key)
	if job.ctx.Err() != nil {
		t.Fatal("HTTP cancellation canceled initialize")
	}
	job.method = "tools/call"
	registry.cancelRequest(p, "owned", key)
	if job.ctx.Err() == nil {
		t.Fatal("ordinary request positive control not canceled")
	}
}

func TestLegacy2025HTTPFramingAdmittedBeforeEgress(t *testing.T) {
	b := &nativeBackendProbe{}
	b.result.Flow.Rows = []NativeFlowRow{{Group: []NativeFlowDimension{{Field: "protocol", Value: "private-framed-row"}}}}
	s := nativeProbeServer(b, nil)
	query := legacyQuery(2, "owned-framing")
	req, failure := decodeLegacy2025RPC(query)
	if failure != nil {
		t.Fatal("fixture request invalid")
	}
	base := s.handleRequest(t.Context(), nativePrincipal(), req, query)
	budget := DefaultNativeFlowRenderBudget()
	budget.WireBytes = len(base) + 7 // final SSE frame needs8 additional bytes
	WithNativeFlowRenderBudget(budget)(s)
	var successes atomic.Int32
	s.gate = ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil }, func(context.Context, ai.EgressEvent) error { successes.Add(1); return nil }, ai.RedactionPolicy{})
	var terminal atomic.Pointer[CallEvent]
	WithCallAudit(func(_ context.Context, event CallEvent) error {
		if event.Phase == CallPhaseTerminal {
			terminal.Store(&event)
		}
		return nil
	})(s)
	socket := httptest.NewTLSServer(s.HTTPHandler(fakeAuthn{p: nativePrincipal()}))
	defer socket.Close()
	response := legacyTLSCall(t, socket, query, "owned", legacyProtocolVersion)
	defer response.Body.Close()
	raw := legacyBody(t, response)
	event := terminal.Load()
	if !bytes.Contains(raw, []byte(nativeResultBudgetMessage)) || bytes.Contains(raw, []byte("private-framed-row")) || successes.Load() != 0 || event == nil || event.Allowed || event.Denial != "result_encoding" {
		t.Fatal("legacy SSE framing escaped budget or recorded successful egress")
	}
}

func TestPublicationPolicySnapshotFreezesSemanticsAndIgnoresRowOrder(t *testing.T) {
	a := []auth.Policy{{ID: "a", Name: "display", Enabled: true, Permission: "flow.read", Effect: auth.PolicyAllow, Subject: map[string]string{"department": "network"}}, {ID: "b", Enabled: true, Permission: "device.read", Effect: auth.PolicyDeny}}
	initial, err := policyAuthoritySet(a)
	if err != nil {
		t.Fatal(err)
	}
	a[0].ID, a[0].Name = "display-id-changed", "renamed"
	b := []auth.Policy{a[1], a[0], a[0]}
	current, err := policyAuthoritySet(b)
	if err != nil || !maps.Equal(initial, current) {
		t.Fatal("non-authority display/order/duplicate changes affected policy snapshot")
	}
	a[0].Subject["department"] = "other"
	current, err = policyAuthoritySet(a)
	if err != nil || maps.Equal(initial, current) {
		t.Fatal("policy authority changed or initial map mutation escaped frozen snapshot")
	}
}
