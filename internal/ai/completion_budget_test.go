// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/breaker"
	"github.com/ctlplne/probectl/internal/flow"
)

func completionTLSModel(t *testing.T, kind ModelKind, handler http.HandlerFunc) *HTTPModel {
	t.Helper()
	socket := httptest.NewTLSServer(handler)
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	model, err := NewHTTPModel(HTTPModelConfig{Kind: kind, Endpoint: socket.URL, Model: "owned-wire-fixture", CAFile: ca, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return model
}

func completionWireFrame(kind ModelKind, text, mode string) map[string]any {
	message := map[string]any{"role": "assistant", "content": text}
	switch kind {
	case KindOllama:
		reason := "stop"
		if mode == "truncated" {
			reason = "length"
		}
		if mode == "unknown" {
			reason = "private_future_reason"
		}
		if mode == "tool" {
			message["tool_calls"] = []any{map[string]any{"function": map[string]any{"name": "private_action"}}}
		}
		frame := map[string]any{"message": message, "done": true, "done_reason": reason}
		if mode == "missing" {
			delete(frame, "done_reason")
		}
		return frame
	case KindOpenAI:
		reason := "stop"
		if mode == "truncated" {
			reason = "length"
		}
		if mode == "unknown" {
			reason = "private_future_reason"
		}
		if mode == "tool" {
			message["tool_calls"] = []any{map[string]any{"function": map[string]any{"name": "private_action"}}}
		}
		if mode == "refusal" {
			message["refusal"] = "private refusal detail"
		}
		choice := map[string]any{"message": message, "finish_reason": reason}
		if mode == "missing" {
			delete(choice, "finish_reason")
		}
		return map[string]any{"choices": []any{choice}}
	default:
		reason := "end_turn"
		if mode == "truncated" {
			reason = "max_tokens"
		}
		if mode == "unknown" {
			reason = "private_future_reason"
		}
		content := []any{map[string]any{"type": "text", "text": text}}
		if mode == "tool" {
			content = append(content, map[string]any{"type": "tool_use", "name": "private_action"})
		}
		if mode == "refusal" {
			reason = "refusal"
		}
		frame := map[string]any{"role": "assistant", "content": content, "stop_reason": reason}
		if mode == "missing" {
			delete(frame, "stop_reason")
		}
		return frame
	}
}

func TestHTTPModelExplicitTruncationNeverPublishesSynthesis(t *testing.T) {
	for _, kind := range []ModelKind{KindOllama, KindOpenAI, KindAnthropic} {
		t.Run(string(kind), func(t *testing.T) {
			model := completionTLSModel(t, kind, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(completionWireFrame(kind, `{"root_cause":"apparently complete","confidence":"high","findings":[]}`, "truncated"))
			})
			synthesis, err := model.Synthesize(t.Context(), SynthesisInput{Question: "owned fixture"})
			if !errors.Is(err, ErrModelCompletionIncomplete) || synthesis.RootCause != "" {
				t.Fatal("explicit token truncation published a syntactically complete partial synthesis", err)
			}
		})
	}
}

func TestBudgetedModelTLSParametersAndExactByteBoundary(t *testing.T) {
	for _, kind := range []ModelKind{KindOllama, KindOpenAI, KindAnthropic} {
		t.Run(string(kind), func(t *testing.T) {
			policy := DefaultCompletionBudget()
			policy.OutputTokens = 12345
			frame, err := json.Marshal(completionWireFrame(kind, `{"status":"ready","plan":{}}`, "complete"))
			if err != nil {
				t.Fatal(err)
			}
			policy.ResponseBytes = int64(len(frame))
			model := completionTLSModel(t, kind, func(w http.ResponseWriter, r *http.Request) {
				var request map[string]json.RawMessage
				if json.NewDecoder(r.Body).Decode(&request) != nil {
					t.Error("invalid completion request")
				}
				if _, exists := request["tools"]; exists {
					t.Error("budgeted completion acquired tools")
				}
				parameter := request[policy.OpenAITokenParameter]
				switch kind {
				case KindOllama:
					var options map[string]json.RawMessage
					_ = json.Unmarshal(request["options"], &options)
					parameter = options["num_predict"]
					if string(request["truncate"]) != "false" || string(request["shift"]) != "false" {
						t.Error("native question allowed silent input/history truncation")
					}
				case KindAnthropic:
					parameter = request["max_tokens"]
				}
				if string(parameter) != fmt.Sprint(policy.OutputTokens) {
					t.Error("operator token policy did not reach provider wire")
				}
				_, _ = w.Write(frame)
			})
			text, err := model.CompleteWithBudget(t.Context(), "static grammar", "owned question", policy)
			if err != nil || text != `{"status":"ready","plan":{}}` {
				t.Fatal("exact response budget failed", err)
			}
			policy.ResponseBytes--
			text, err = model.CompleteWithBudget(t.Context(), "static grammar", "owned question", policy)
			if !errors.Is(err, ErrModelCompletionBudget) || text != "" {
				t.Fatal("one-past body budget released partial output", err)
			}
		})
	}
}

func TestBudgetedModelTLSRefusesIncompleteToolAndRefusalOutput(t *testing.T) {
	for _, kind := range []ModelKind{KindOllama, KindOpenAI, KindAnthropic} {
		for _, mode := range []string{"truncated", "unknown", "missing", "tool", "refusal"} {
			if kind == KindOllama && mode == "refusal" {
				continue
			}
			t.Run(string(kind)+"/"+mode, func(t *testing.T) {
				model := completionTLSModel(t, kind, func(w http.ResponseWriter, _ *http.Request) {
					_ = json.NewEncoder(w).Encode(completionWireFrame(kind, `{"status":"ready","plan":{}}`, mode))
				})
				text, err := model.CompleteWithBudget(t.Context(), "grammar", "owned question", DefaultCompletionBudget())
				if !errors.Is(err, ErrModelCompletionIncomplete) || text != "" || strings.Contains(err.Error(), "private") {
					t.Fatal("incomplete provider response was released or copied", err)
				}
				planner, err := NewModelFlowQuestionPlanner(NewGatedCompleter(model, nil), DefaultFlowQuestionBudget())
				if err != nil {
					t.Fatal(err)
				}
				proposal, err := planner.Plan(t.Context(), modelQuestionInput())
				if err == nil || proposal.Plan != nil || strings.Contains(err.Error(), "private") {
					t.Fatal("incomplete provider response became a plan", err)
				}
			})
		}
	}
}

func TestBudgetedModelFullLargeGrammarThroughTLSResilienceAndGate(t *testing.T) {
	plan := questionReachPlan()
	pattern := strings.Repeat("a", flow.MaxQueryRegexBytes)
	for group := range plan.Filter.Groups {
		for index := range plan.Filter.Groups[group].Conditions {
			plan.Filter.Groups[group].Conditions[index] = flow.QueryPredicate{Field: "src_as_name", Op: flow.QueryRegex, Values: []string{pattern}}
		}
	}
	raw := questionProposalJSON(t, FlowQuestionProposal{Status: FlowQuestionReady, Plan: &plan})
	if len(raw) <= 1<<20 {
		t.Fatal("large grammar did not cross old response ceiling")
	}
	for _, kind := range []ModelKind{KindOllama, KindOpenAI, KindAnthropic} {
		t.Run(string(kind), func(t *testing.T) {
			model := completionTLSModel(t, kind, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(completionWireFrame(kind, raw, "complete"))
			})
			resilient := NewResilientModel(model, NewBuiltinModel(), 10*time.Second)
			policy := DefaultCompletionBudget()
			policy.OutputTokens = 600000 // Explicit fixture resource policy; no provider capacity claim.
			planner, err := NewModelFlowQuestionPlanner(NewGatedCompleter(resilient, nil), DefaultFlowQuestionBudget(), policy)
			if err != nil {
				t.Fatal(err)
			}
			proposal, err := planner.Plan(t.Context(), modelQuestionInput())
			if err != nil || proposal.Plan.RowLimit != 50000 || proposal.Plan.PageSize != 5000 || len(proposal.Plan.Metrics) != 78 || proposal.Plan.Filter.Groups[3].Conditions[249].Values[0] != pattern {
				t.Fatal("actual adapter path lost full native grammar", err)
			}
		})
	}
}

func TestBudgetedModelCostRefusalDoesNotPoisonSharedProviderHealth(t *testing.T) {
	var phase atomic.Int32
	var calls atomic.Int32
	model := completionTLSModel(t, KindOllama, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		if phase.Load() == 2 {
			http.Error(w, "private provider diagnostic", http.StatusServiceUnavailable)
			return
		}
		mode := "complete"
		if phase.Load() == 0 {
			mode = "truncated"
		}
		_ = json.NewEncoder(w).Encode(completionWireFrame(KindOllama, `{"status":"ready","plan":{}}`, mode))
	})
	resilient := NewResilientModel(model, NewBuiltinModel(), 10*time.Second)
	for range 4 {
		if text, err := resilient.CompleteWithBudget(t.Context(), "grammar", "costly question", DefaultCompletionBudget()); !errors.Is(err, ErrModelCompletionBudget) || text != "" {
			t.Fatal("cost refusal changed", err)
		}
	}
	if stats := resilient.br.Stats(); stats.State != breaker.StateClosed || stats.ConsecFailures != 0 {
		t.Fatal("per-question cost poisoned provider health", stats)
	}
	phase.Store(1)
	if _, err := resilient.Complete(t.Context(), "grammar", "healthy sibling"); err != nil {
		t.Fatal("costly sibling denied ordinary authoring", err)
	}
	phase.Store(2)
	for range 3 {
		_, _ = resilient.CompleteWithBudget(t.Context(), "grammar", "outage", DefaultCompletionBudget())
	}
	before := calls.Load()
	if _, err := resilient.CompleteWithBudget(t.Context(), "grammar", "outage", DefaultCompletionBudget()); !errors.Is(err, breaker.ErrOpen) || calls.Load() != before {
		t.Fatal("real provider outage no longer trips shared breaker", err)
	}
}

func TestTruncatedSynthesisUsesMarkedFallbackWithoutCacheOrHealthPoison(t *testing.T) {
	var complete atomic.Bool
	var calls atomic.Int32
	model := completionTLSModel(t, KindOllama, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		mode := "truncated"
		if complete.Load() {
			mode = "complete"
		}
		_ = json.NewEncoder(w).Encode(completionWireFrame(KindOllama, `{"root_cause":"complete result","confidence":"high","findings":[]}`, mode))
	})
	resilient := NewResilientModel(model, NewBuiltinModel(), 10*time.Second)
	input := SynthesisInput{Question: "same owned question"}
	for range 4 {
		syn, err := resilient.Synthesize(t.Context(), input)
		if err != nil || !syn.Degraded || !strings.Contains(syn.RootCause, "model output resource limit") {
			t.Fatal("truncation was presented as a complete synthesis", err)
		}
	}
	if calls.Load() != 4 || resilient.br.Stats().State != breaker.StateClosed {
		t.Fatal("partial response cached or poisoned shared health")
	}
	complete.Store(true)
	syn, err := resilient.Synthesize(t.Context(), input)
	if err != nil || syn.Degraded || syn.RootCause != "complete result" {
		t.Fatal("recovered complete synthesis not served", err)
	}
	_, _ = resilient.Synthesize(t.Context(), input)
	if calls.Load() != 5 {
		t.Fatal("complete synthesis no longer uses its normal cache")
	}
}

func TestCompletionBudgetRejectsUnboundedPoliciesBeforeDispatch(t *testing.T) {
	for _, policy := range []CompletionBudget{{}, {ResponseBytes: -1, OutputTokens: 1, OpenAITokenParameter: "max_tokens"}, {ResponseBytes: 1, OutputTokens: 0, OpenAITokenParameter: "max_tokens"}, {ResponseBytes: 1, OutputTokens: 1, OpenAITokenParameter: "arbitrary"}} {
		var calls atomic.Int32
		model := completionTLSModel(t, KindOllama, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
		if _, err := model.CompleteWithBudget(context.Background(), "grammar", "question", policy); !errors.Is(err, ErrModelCompletionBudget) || calls.Load() != 0 {
			t.Fatal("invalid resource policy reached a provider", err)
		}
	}
}

func TestBudgetedModelExplicitLegacyTokenParameter(t *testing.T) {
	model := completionTLSModel(t, KindOpenAI, func(w http.ResponseWriter, r *http.Request) {
		var request map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&request) != nil || string(request["max_tokens"]) != "7777" || request["max_completion_tokens"] != nil {
			t.Error("explicit compatible-endpoint token selector was ignored or sent both controls")
		}
		_ = json.NewEncoder(w).Encode(completionWireFrame(KindOpenAI, `{"status":"ready","plan":{}}`, "complete"))
	})
	policy := DefaultCompletionBudget()
	policy.OpenAITokenParameter, policy.OutputTokens = "max_tokens", 7777
	if _, err := model.CompleteWithBudget(t.Context(), "grammar", "owned", policy); err != nil {
		t.Fatal(err)
	}
}

func TestBudgetedModelAssemblesAllTextWithoutThinking(t *testing.T) {
	model := completionTLSModel(t, KindAnthropic, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"role": "assistant", "stop_reason": "end_turn", "content": []any{
			map[string]string{"type": "thinking", "thinking": "private model reasoning"},
			map[string]string{"type": "text", "text": `{"status":"ready",`},
			map[string]string{"type": "redacted_thinking", "data": "private opaque reasoning"},
			map[string]string{"type": "text", "text": `"plan":{}}`},
		}})
	})
	text, err := model.CompleteWithBudget(t.Context(), "grammar", "owned", DefaultCompletionBudget())
	if err != nil || text != `{"status":"ready","plan":{}}` || strings.Contains(text, "private") {
		t.Fatal("text block lost or reasoning disclosed", err)
	}
}

func TestBudgetedModelCancellationDoesNotReleaseLateText(t *testing.T) {
	started, ended := make(chan struct{}), make(chan struct{})
	model := completionTLSModel(t, KindOllama, func(_ http.ResponseWriter, r *http.Request) {
		var request map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("request did not arrive intact")
		}
		close(started)
		<-r.Context().Done()
		close(ended)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		text, err := model.CompleteWithBudget(ctx, "grammar", "owned", DefaultCompletionBudget())
		if text != "" {
			done <- errors.New("canceled completion released text")
			return
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("owned TLS request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("canceled completion did not return cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled TLS completion did not stop")
	}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not reach owned TLS service")
	}
}
