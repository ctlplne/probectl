// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/breaker"
)

func TestResilientModelCallerCancellationCannotPoisonSiblingHealth(t *testing.T) {
	for _, operation := range []string{"synthesis", "authoring", "native-plan"} {
		t.Run(operation, func(t *testing.T) {
			var calls atomic.Int32
			model := completionTLSModel(t, KindOllama, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_ = json.NewEncoder(w).Encode(completionWireFrame(KindOllama, `{"status":"ready","plan":{}}`, "complete"))
			})
			resilient := NewResilientModel(model, NewBuiltinModel(), 10*time.Second)
			var wrongError bool
			for range 3 {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				var err error
				switch operation {
				case "synthesis":
					var synthesis Synthesis
					synthesis, err = resilient.Synthesize(ctx, SynthesisInput{Question: "owned question"})
					wrongError = wrongError || synthesis.RootCause != ""
				case "authoring":
					_, err = resilient.Complete(ctx, "grammar", "owned")
				default:
					_, err = resilient.CompleteWithBudget(ctx, "grammar", "owned", DefaultCompletionBudget())
				}
				wrongError = wrongError || !errors.Is(err, context.Canceled)
			}
			if stats := resilient.br.Stats(); stats.State != breaker.StateClosed || stats.ConsecFailures != 0 || calls.Load() != 0 || wrongError {
				t.Fatalf("caller cancellation published fallback or poisoned healthy sibling: stats=%+v calls=%d wrong_error=%v", stats, calls.Load(), wrongError)
			}
			if _, err := resilient.CompleteWithBudget(t.Context(), "grammar", "healthy sibling", DefaultCompletionBudget()); err != nil || calls.Load() != 1 {
				t.Fatal("canceled caller prevented healthy sibling completion", err)
			}
		})
	}
}

func TestResilientModelPolicyRefusalCannotPoisonSiblingHealth(t *testing.T) {
	for _, kind := range []ModelKind{KindOpenAI, KindAnthropic} {
		t.Run(string(kind), func(t *testing.T) {
			var allowed atomic.Bool
			model := completionTLSModel(t, kind, func(w http.ResponseWriter, _ *http.Request) {
				mode := "refusal"
				if allowed.Load() {
					mode = "complete"
				}
				_ = json.NewEncoder(w).Encode(completionWireFrame(kind, `{"status":"ready","plan":{}}`, mode))
			})
			resilient := NewResilientModel(model, NewBuiltinModel(), 10*time.Second)
			for range 3 {
				if text, err := resilient.CompleteWithBudget(t.Context(), "grammar", "refused question", DefaultCompletionBudget()); !errors.Is(err, ErrModelCompletionIncomplete) || text != "" {
					t.Fatal("provider refusal released a plan", err)
				}
			}
			if stats := resilient.br.Stats(); stats.State != breaker.StateClosed || stats.ConsecFailures != 0 {
				t.Fatal("normal provider refusal poisoned sibling health", stats)
			}
			allowed.Store(true)
			if _, err := resilient.CompleteWithBudget(t.Context(), "grammar", "healthy sibling", DefaultCompletionBudget()); err != nil {
				t.Fatal("refused questions blocked healthy sibling", err)
			}
		})
	}
}

func TestResilientModelInflightAbortPreservesPriorHealthAndNoFallback(t *testing.T) {
	for _, operation := range []string{"synthesis", "authoring", "native-plan"} {
		t.Run(operation, func(t *testing.T) {
			started, ended := make(chan struct{}), make(chan struct{})
			model := completionTLSModel(t, KindOllama, func(_ http.ResponseWriter, r *http.Request) {
				var body map[string]json.RawMessage
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("owned request did not arrive intact")
				}
				close(started)
				<-r.Context().Done()
				close(ended)
			})
			resilient := NewResilientModel(model, NewBuiltinModel(), 10*time.Second)
			_ = resilient.br.DoWithOutcome(func() (breaker.Outcome, error) { return breaker.OutcomeFailure, errors.New("prior owned failure") })
			before := resilient.br.Stats()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var err error
				switch operation {
				case "synthesis":
					var syn Synthesis
					syn, err = resilient.Synthesize(ctx, SynthesisInput{Question: "owned"})
					if syn.RootCause != "" {
						err = errors.New("canceled request published fallback")
					}
				case "authoring":
					_, err = resilient.Complete(ctx, "grammar", "owned")
				default:
					_, err = resilient.CompleteWithBudget(ctx, "grammar", "owned", DefaultCompletionBudget())
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
					t.Fatal("canceled request did not return cancellation", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("canceled request did not stop")
			}
			select {
			case <-ended:
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation did not reach actual TLS service")
			}
			if resilient.br.Stats() != before || resilient.degradations() != 0 {
				t.Fatal("aborted call changed health or published fallback", resilient.br.Stats())
			}
		})
	}
}

func TestResilientModelCallerCancellationCannotReadCachedSynthesis(t *testing.T) {
	var calls atomic.Int32
	model := completionTLSModel(t, KindOllama, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(completionWireFrame(KindOllama, `{"root_cause":"cached complete","confidence":"low","findings":[]}`, "complete"))
	})
	resilient := NewResilientModel(model, NewBuiltinModel(), 10*time.Second)
	input := SynthesisInput{Question: "owned cached question"}
	if _, err := resilient.Synthesize(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if syn, err := resilient.Synthesize(ctx, input); !errors.Is(err, context.Canceled) || syn.RootCause != "" || resilient.cacheHitCount() != 0 || calls.Load() != 1 {
		t.Fatal("canceled caller received cached synthesis", err)
	}
}

func TestResilientModelOwnTimeoutStillMarksProviderUnhealthy(t *testing.T) {
	model := completionTLSModel(t, KindOllama, func(_ http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&body)
		<-r.Context().Done()
	})
	resilient := NewResilientModel(model, NewBuiltinModel(), 50*time.Millisecond)
	resilient.br = breaker.New(1, time.Minute)
	if _, err := resilient.CompleteWithBudget(t.Context(), "grammar", "owned", DefaultCompletionBudget()); !errors.Is(err, context.DeadlineExceeded) || resilient.br.Stats().State != breaker.StateOpen {
		t.Fatal("adapter timeout was misclassified as a caller abort", err, resilient.br.Stats())
	}
}

func TestResilientModelCallerDeadlinePreservesExistingHealth(t *testing.T) {
	model := completionTLSModel(t, KindOllama, func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("expired caller reached the provider")
	})
	resilient := NewResilientModel(model, NewBuiltinModel(), time.Second)
	_ = resilient.br.DoWithOutcome(func() (breaker.Outcome, error) { return breaker.OutcomeFailure, errors.New("prior owned failure") })
	before := resilient.br.Stats()
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if syn, err := resilient.Synthesize(ctx, SynthesisInput{Question: "owned"}); !errors.Is(err, context.DeadlineExceeded) || syn.RootCause != "" {
		t.Fatal("expired caller received a synthesis or fallback", err)
	}
	if text, err := resilient.Complete(ctx, "grammar", "owned"); !errors.Is(err, context.DeadlineExceeded) || text != "" {
		t.Fatal("expired caller received authored text", err)
	}
	if text, err := resilient.CompleteWithBudget(ctx, "grammar", "owned", DefaultCompletionBudget()); !errors.Is(err, context.DeadlineExceeded) || text != "" {
		t.Fatal("expired caller received a native plan", err)
	}
	if resilient.br.Stats() != before || resilient.degradations() != 0 {
		t.Fatal("caller deadline changed shared health or published fallback", resilient.br.Stats())
	}
	// Once dispatch has started, a deadline owned by the caller remains neutral;
	// an adapter's own child timeout with a live parent remains a failure.
	if modelHealthOutcome(ctx, context.DeadlineExceeded) != breaker.OutcomeNeutral || modelHealthOutcome(t.Context(), context.DeadlineExceeded) != breaker.OutcomeFailure {
		t.Fatal("caller and adapter deadlines have the same health classification")
	}
}

func TestResilientModelMalformedRefusalStillCountsProtocolFailure(t *testing.T) {
	for _, mode := range []string{"wrong type", "wrong role"} {
		t.Run(mode, func(t *testing.T) {
			model := completionTLSModel(t, KindOpenAI, func(w http.ResponseWriter, _ *http.Request) {
				frame := completionWireFrame(KindOpenAI, `{"status":"ready","plan":{}}`, "refusal")
				message := frame["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)
				if mode == "wrong type" {
					message["refusal"] = map[string]string{"private": "diagnostic"}
				} else {
					message["role"] = "user"
				}
				_ = json.NewEncoder(w).Encode(frame)
			})
			resilient := NewResilientModel(model, NewBuiltinModel(), 10*time.Second)
			text, err := resilient.CompleteWithBudget(t.Context(), "grammar", "owned", DefaultCompletionBudget())
			if !errors.Is(err, ErrModelCompletionIncomplete) || errors.Is(err, ErrModelCompletionRefused) || text != "" || resilient.br.Stats().ConsecFailures != 1 {
				t.Fatal("malformed metadata manufactured healthy refusal", err, resilient.br.Stats())
			}
		})
	}
}
