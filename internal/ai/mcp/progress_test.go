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
	"io"
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

func progressRequest(t *testing.T, token any) []byte {
	t.Helper()
	raw := modernRequest("tools/call", map[string]any{"name": "flow_explorer_query", "arguments": map[string]any{"plan": map[string]any{}}})
	var request map[string]any
	if json.Unmarshal(raw, &request) != nil {
		t.Fatal("fixture request invalid")
	}
	request["params"].(map[string]any)["_meta"].(map[string]any)["progressToken"] = token
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func modernTLSCall(t *testing.T, socket *httptest.Server, raw []byte) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer owned-stream-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", modernProtocolVersion)
	request.Header.Set("Mcp-Method", "tools/call")
	request.Header.Set("Mcp-Name", "flow_explorer_query")
	response, err := socket.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestModernHTTPProgressIsBoundedAndEndsWithRedactedCompleteResult(t *testing.T) {
	b := &nativeBackendProbe{}
	b.result.Flow.Rows = []NativeFlowRow{{Group: []NativeFlowDimension{{Field: "protocol", Value: "private-source-row"}}}}
	s := nativeProbeServer(b, nil)
	socket := httptest.NewTLSServer(s.HTTPHandler(fakeAuthn{p: nativePrincipal()}))
	defer socket.Close()
	response := modernTLSCall(t, socket, progressRequest(t, "owned-progress-token"))
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "text/event-stream" || response.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatal("progress did not use a request-scoped SSE stream")
	}
	var messages [][]byte
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 1024), 1<<20)
	for scanner.Scan() {
		if line := scanner.Text(); strings.HasPrefix(line, "data: ") {
			messages = append(messages, []byte(strings.TrimPrefix(line, "data: ")))
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(messages) != 3 {
		t.Fatal("unbounded or missing progress/final messages", len(messages))
	}
	for index, raw := range messages[:2] {
		var notice struct {
			Method string `json:"method"`
			Params struct {
				Token    string `json:"progressToken"`
				Progress int    `json:"progress"`
			} `json:"params"`
		}
		if json.Unmarshal(raw, &notice) != nil || notice.Method != "notifications/progress" || notice.Params.Token != "owned-progress-token" || notice.Params.Progress != index || bytes.Contains(raw, []byte("private-source-row")) {
			t.Fatal("progress exposed source content or fabricated progress")
		}
	}
	if !bytes.Contains(messages[2], []byte(`"resultType":"complete"`)) || !bytes.Contains(messages[2], []byte("private-source-row")) {
		t.Fatal("stream ended without the complete result")
	}
}

type cancelNativeBackend struct {
	*nativeBackendProbe
	canceled chan struct{}
	started  chan struct{}
}

func (b *cancelNativeBackend) FlowQuery(ctx context.Context, _ *auth.Principal, _ flow.QueryPlan) (NativeFlowQueryResult, error) {
	close(b.started)
	<-ctx.Done()
	close(b.canceled)
	return NativeFlowQueryResult{}, ctx.Err()
}

func TestModernHTTPDisconnectCancelsSourceAndReleasesAdmission(t *testing.T) {
	b := &cancelNativeBackend{nativeBackendProbe: &nativeBackendProbe{}, canceled: make(chan struct{}), started: make(chan struct{})}
	var active, releases atomic.Int32
	released := make(chan struct{}, 1)
	s := nativeProbeServer(b, func(context.Context, *auth.Principal) (func(), error) {
		active.Add(1)
		return func() { active.Add(-1); releases.Add(1); released <- struct{}{} }, nil
	})
	socket := httptest.NewTLSServer(s.HTTPHandler(fakeAuthn{p: nativePrincipal()}))
	defer socket.Close()
	response := modernTLSCall(t, socket, progressRequest(t, 123))
	defer func() { _ = response.Body.Close() }()
	reader := bufio.NewReader(response.Body)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, "notifications/progress") || active.Load() != 1 {
		t.Fatal("query not admitted before streaming", err)
	}
	select {
	case <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("source did not start after admission")
	}
	_ = response.Body.Close()
	select {
	case <-b.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("client disconnect did not cancel source")
	}
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("canceled source retained admission")
	}
	if active.Load() != 0 || releases.Load() != 1 {
		t.Fatal("query admission released incorrectly")
	}
}

func TestModernMetadataParticipatesInFinalBudgetBeforeEgress(t *testing.T) {
	b := &nativeBackendProbe{}
	s := nativeProbeServer(b, nil)
	legacy := s.Handle(t.Context(), nativePrincipal(), nativeRequest("flow_explorer_query", map[string]any{"plan": map[string]any{}}))
	budget := DefaultNativeFlowRenderBudget()
	budget.WireBytes = len(legacy) + 1
	WithNativeFlowRenderBudget(budget)(s)
	var egress atomic.Int32
	s.gate = ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil }, func(context.Context, ai.EgressEvent) error { egress.Add(1); return nil }, ai.RedactionPolicy{})
	var terminal CallEvent
	WithCallAudit(func(_ context.Context, event CallEvent) error {
		if event.Phase == CallPhaseTerminal {
			terminal = event
		}
		return nil
	})(s)
	raw := s.Handle(t.Context(), nativePrincipal(), modernRequest("tools/call", map[string]any{"name": "flow_explorer_query", "arguments": map[string]any{"plan": map[string]any{}}}))
	if !bytes.Contains(raw, []byte(nativeResultBudgetMessage)) || egress.Load() != 0 || terminal.Allowed || terminal.Denial != "result_encoding" {
		t.Fatal("modern envelope overhead escaped admission or recorded success")
	}
}

func TestModernProgressTokenRejectsFractionalAndOpaqueValues(t *testing.T) {
	for _, token := range []any{1.25, true, nil, map[string]any{"private": "value"}} {
		_, failure := decodeRPC(progressRequest(t, token), true)
		if failure == nil || failure.Error.Code != codeInvalidParams {
			t.Fatal("non-integer/string progress token accepted")
		}
	}
}

// A caller's progress token is echoed only as a JSON string in an explicitly
// typed event stream. HTML metacharacters and event separators retain their
// exact decoded value without becoming response markup or extra SSE frames.
func TestModernHTTPProgressTokenCannotInjectHTMLOrEvents(t *testing.T) {
	token := "<script>alert(1)</script>\n\ndata: forged-event"
	backend := &nativeBackendProbe{}
	server := nativeProbeServer(backend, nil)
	socket := httptest.NewTLSServer(server.HTTPHandler(fakeAuthn{p: nativePrincipal()}))
	defer socket.Close()
	response := modernTLSCall(t, socket, progressRequest(t, token))
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal("progress response lost its non-HTML media boundary", err)
	}
	if bytes.Contains(body, []byte("<script")) || bytes.Contains(body, []byte("\n\ndata: forged-event")) {
		t.Fatal("progress token became raw markup or an injected event")
	}
	frames := 0
	for _, line := range bytes.Split(body, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("data: ")) {
			continue
		}
		var frame struct {
			Method string `json:"method"`
			Params struct {
				Token string `json:"progressToken"`
			} `json:"params"`
		}
		if err := json.Unmarshal(bytes.TrimPrefix(line, []byte("data: ")), &frame); err != nil {
			t.Fatal("progress framing contains unencoded caller bytes", err)
		}
		if frame.Method == "notifications/progress" && frame.Params.Token != token {
			t.Fatal("progress safety narrowed the supported correlation value")
		}
		frames++
	}
	if frames != 3 {
		t.Fatal("progress token changed the number of bounded service frames", frames)
	}
}
