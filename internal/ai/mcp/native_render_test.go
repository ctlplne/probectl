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
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
)

func TestNativeRenderConfiguredCostsRefuseAtomicallyAndAdmitSameResult(t *testing.T) {
	backend := &nativeBackendProbe{}
	for i := 0; i < 30; i++ {
		backend.result.Flow.Rows = append(backend.result.Flow.Rows, NativeFlowRow{Group: []NativeFlowDimension{{Field: "exporter", Value: strings.Repeat("render-fixture-", 40)}}})
	}
	for _, cost := range []string{"source", "wire", "nodes"} {
		t.Run(cost, func(t *testing.T) {
			budget := DefaultNativeFlowRenderBudget()
			switch cost {
			case "source":
				budget.SourceBytes = 1024
			case "wire":
				budget.WireBytes = 1024
			case "nodes":
				budget.Nodes = 32
			}
			server := nativeProbeServer(backend, nil)
			WithNativeFlowRenderBudget(budget)(server)
			var events []CallEvent
			WithCallAudit(func(_ context.Context, e CallEvent) error { events = append(events, e); return nil })(server)
			raw := server.Handle(t.Context(), nativePrincipal(), nativeRequest("flow_explorer_query", map[string]any{"plan": map[string]any{}}))
			if !bytes.Contains(raw, []byte(nativeResultBudgetMessage)) || bytes.Contains(raw, []byte("render-fixture-")) || len(events) != 2 || events[1].Allowed || events[1].Denial != "result_encoding" {
				t.Fatal("cost refusal returned partial telemetry or a successful terminal audit")
			}
			WithNativeFlowRenderBudget(DefaultNativeFlowRenderBudget())(server)
			raw = server.Handle(t.Context(), nativePrincipal(), nativeRequest("flow_explorer_query", map[string]any{"plan": map[string]any{}}))
			if !bytes.Contains(raw, []byte("render-fixture-")) || !events[len(events)-1].Allowed {
				t.Fatal("higher operator cost did not admit the same valid result")
			}
		})
	}
}

func TestNativeRenderHigherWireBudgetHasNoHiddenDefaultCeiling(t *testing.T) {
	b := &nativeBackendProbe{}
	b.result.Flow.Rows = []NativeFlowRow{{Group: []NativeFlowDimension{{Field: "exporter", Value: strings.Repeat("r", 1<<20)}}}}
	server := nativeProbeServer(b, nil)
	budget := DefaultNativeFlowRenderBudget()
	budget.WireBytes++ // Higher than the old hardcoded native ceiling.
	WithNativeFlowRenderBudget(budget)(server)
	response := server.Handle(t.Context(), nativePrincipal(), nativeRequest("flow_explorer_query", map[string]any{"plan": map[string]any{}}))
	if !json.Valid(response) || len(response) <= maxMCPToolResultBytes || bytes.Contains(response, []byte(`"isError":true`)) || bytes.Contains(response, []byte(`"error":`)) {
		t.Fatal("a larger configured native wire budget fell back to legacy admission")
	}
	if _, err := server.redactedToolResult("tenant-native", b.result, false); err == nil {
		t.Fatal("native configuration weakened legacy render admission")
	}
}

func TestNativeRenderFinalEnvelopeRefusalIsNotSuccessfulEgress(t *testing.T) {
	b := &nativeBackendProbe{}
	server := nativeProbeServer(b, nil)
	result, err := server.redactedToolResult("tenant-native", b.result, true)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := marshalBoundedJSONNodes(result, 1<<20, false, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	budget := DefaultNativeFlowRenderBudget()
	budget.WireBytes = len(encoded) + 1 // Fits the result, not its RPC envelope.
	WithNativeFlowRenderBudget(budget)(server)
	var terminal CallEvent
	WithCallAudit(func(_ context.Context, e CallEvent) error {
		if e.Phase == CallPhaseTerminal {
			terminal = e
		}
		return nil
	})(server)
	egress := 0
	server.gate = ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil }, func(context.Context, ai.EgressEvent) error { egress++; return nil }, ai.RedactionPolicy{})
	response := server.Handle(t.Context(), nativePrincipal(), nativeRequest("flow_explorer_query", map[string]any{"plan": map[string]any{}}))
	if !bytes.Contains(response, []byte(nativeResultBudgetMessage)) || terminal.Allowed || terminal.Denial != "result_encoding" || egress != 0 {
		t.Fatal("final framing overflow recorded successful egress or returned telemetry")
	}
}

func TestNativeRenderInvalidConfigurationNeverInvokesBackend(t *testing.T) {
	for _, value := range []int{0, -1, int(^uint(0) >> 1)} {
		b := &nativeBackendProbe{}
		server := nativeProbeServer(b, nil)
		budget := DefaultNativeFlowRenderBudget()
		budget.WireBytes = value
		WithNativeFlowRenderBudget(budget)(server)
		response := server.Handle(t.Context(), nativePrincipal(), nativeRequest("flow_explorer_query", map[string]any{"plan": map[string]any{}}))
		if b.calls != 0 || rpcErrorCode(response) != codeUnavailable {
			t.Fatal("invalid render configuration invoked a data source")
		}
	}
}
