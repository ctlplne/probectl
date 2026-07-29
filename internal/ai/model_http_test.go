// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/httpbody"
)

// A local Ollama server (loopback, plaintext) — the air-gapped path. Proves the
// HTTP adapter works with no cloud and no TLS to a co-located model.
func TestHTTPModelOllamaAirGapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		answer := `{"root_cause":"link flap","confidence":"high","insufficient_evidence":false,"findings":[{"statement":"flapping interface","citations":["E1"]}]}`
		_ = json.NewEncoder(w).Encode(map[string]any{"message": map[string]string{"content": answer}})
	}))
	defer srv.Close()

	m, err := NewHTTPModel(HTTPModelConfig{Kind: KindOllama, Endpoint: srv.URL, Model: "llama3.1"})
	if err != nil {
		t.Fatal(err)
	}
	syn, err := m.Synthesize(context.Background(), SynthesisInput{Question: "q", Evidence: []Evidence{{ID: "E1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if syn.RootCause != "link flap" || syn.Confidence != ConfidenceHigh || len(syn.Findings) != 1 {
		t.Errorf("synthesis = %+v", syn)
	}
}

// End-to-end through the Analyzer with the local model: citation integrity is
// still enforced on the model's output (a hallucinated id is dropped).
func TestAnalyzeWithLocalModelEndToEnd(t *testing.T) {
	// The fake model cites the FIRST REAL evidence id it sees in the prompt
	// (ids are per-session random now, U-037) plus a hallucinated one.
	idRe := regexp.MustCompile(`E[0-9a-f]+-1\b`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		realID := idRe.FindString(string(body))
		answer := `{"root_cause":"x","confidence":"medium","findings":[{"statement":"s","citations":["` + realID + `","E42"]}]}`
		_ = json.NewEncoder(w).Encode(map[string]any{"message": map[string]string{"content": answer}})
	}))
	defer srv.Close()
	m, _ := NewHTTPModel(HTTPModelConfig{Kind: KindOllama, Endpoint: srv.URL, Model: "m"})

	fs := fixtureSource{entities: []Row{{"id": "inc-1", "kind": "incident", "plane": "network", "title": "real"}}}
	ans, err := NewAnalyzer(engineWith(fs), WithModel(m)).Analyze(
		context.Background(), principal("t", PermEntitiesRead), Question{Text: "what happened?"})
	if err != nil {
		t.Fatal(err)
	}
	if !citationsResolve(ans) {
		t.Errorf("local-model answer must still pass citation integrity: %+v", ans)
	}
	if len(ans.Findings) != 1 || len(ans.Findings[0].Citations) != 1 {
		t.Errorf("hallucinated E42 should be dropped, got %+v", ans.Findings)
	}
}

func TestHTTPModelOpenAIParsesFencedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer sk-test" {
			t.Errorf("auth header = %q", got)
		}
		content := "```json\n{\"root_cause\":\"y\",\"confidence\":\"low\",\"findings\":[]}\n```"
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]string{"content": content}}}})
	}))
	defer srv.Close()
	m, _ := NewHTTPModel(HTTPModelConfig{Kind: KindOpenAI, Endpoint: srv.URL, Model: "gpt", Token: "sk-test"})
	syn, err := m.Synthesize(context.Background(), SynthesisInput{Question: "q"})
	if err != nil {
		t.Fatal(err)
	}
	if !syn.InsufficientEvidence { // no findings → cannot ground a claim
		t.Errorf("empty findings should mark insufficient, got %+v", syn)
	}
}

func TestHTTPModelTLSPolicy(t *testing.T) {
	if _, err := NewHTTPModel(HTTPModelConfig{Kind: KindOpenAI, Endpoint: "http://api.example.com"}); err == nil {
		t.Error("plaintext to a non-loopback host must be refused (guardrail 12)")
	}
	if _, err := NewHTTPModel(HTTPModelConfig{Kind: KindOpenAI, Endpoint: "https://api.example.com"}); err != nil {
		t.Errorf("https remote should be accepted: %v", err)
	}
	if _, err := NewHTTPModel(HTTPModelConfig{Kind: KindOllama, Endpoint: "http://localhost:11434"}); err != nil {
		t.Errorf("loopback plaintext (local model) should be accepted: %v", err)
	}
	if _, err := NewHTTPModel(HTTPModelConfig{Kind: KindOllama, Endpoint: "http://127.0.0.1:11434"}); err != nil {
		t.Errorf("loopback IP plaintext should be accepted: %v", err)
	}
	if _, err := NewHTTPModel(HTTPModelConfig{Endpoint: "https://x"}); err == nil {
		t.Error("missing kind should error")
	}
}

func TestHTTPModelRejectsCredentialBearingEndpointWithoutDisclosure(t *testing.T) {
	for name, endpoint := range map[string]string{
		"remote":   "https://model-user:model-secret@api.example.com/v1",
		"loopback": "http://local-user:local-secret@127.0.0.1:11434",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewHTTPModel(HTTPModelConfig{Kind: KindOpenAI, Endpoint: endpoint})
			if err == nil {
				t.Fatal("credential-bearing model endpoint should fail closed")
			}
			for _, secret := range []string{"model-user", "model-secret", "local-user", "local-secret", endpoint} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("model validation error disclosed endpoint credential %q: %v", secret, err)
				}
			}
		})
	}
}

func TestHTTPModelErrorsOnNon2xx(t *testing.T) {
	const hostileBody = "provider-secret-body customer=alice@example.com token=remote-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, hostileBody, http.StatusTooManyRequests)
	}))
	defer srv.Close()
	m, _ := NewHTTPModel(HTTPModelConfig{Kind: KindOllama, Endpoint: srv.URL, Model: "m"})
	_, err := m.Synthesize(context.Background(), SynthesisInput{Question: "q"})
	if err == nil {
		t.Error("non-2xx should error")
	}
	if got := err.Error(); strings.Contains(got, hostileBody) || strings.Contains(got, "remote-secret") {
		t.Fatalf("non-2xx error disclosed the untrusted provider body: %q", got)
	} else if !strings.Contains(got, "ollama") || !strings.Contains(got, "429") {
		t.Fatalf("non-2xx error lost bounded provider/status context: %q", got)
	}
}

type fixedModelResponseTransport struct {
	body string
}

func (t fixedModelResponseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(t.body)),
	}, nil
}

func modelResponseAtSize(t *testing.T, size int) string {
	t.Helper()
	const prefix = `{"message":{"content":"`
	const suffix = `"}}`
	if size < len(prefix)+len(suffix) {
		t.Fatalf("response size %d is too small for fixture", size)
	}
	return prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix
}

func TestHTTPModelResponseExactLimitAndOnePast(t *testing.T) {
	const limit = 1 << 20
	var out struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	model := &HTTPModel{
		client: &http.Client{Transport: fixedModelResponseTransport{
			body: modelResponseAtSize(t, limit),
		}},
	}
	if err := model.post(context.Background(), "https://model.example.test", nil, map[string]string{"prompt": "x"}, &out); err != nil {
		t.Fatalf("exact-limit response must pass: %v", err)
	}
	if out.Message.Content == "" {
		t.Fatal("exact-limit response was not decoded")
	}

	model.client.Transport = fixedModelResponseTransport{body: modelResponseAtSize(t, limit+1)}
	out.Message.Content = ""
	err := model.post(context.Background(), "https://model.example.test", nil, map[string]string{"prompt": "x"}, &out)
	if !errors.Is(err, httpbody.ErrTooLarge) {
		t.Fatalf("one-past response = %v, want ErrTooLarge before JSON decoding", err)
	}
	if out.Message.Content != "" {
		t.Fatal("one-past response partially decoded into output")
	}
}

func TestExtractJSON(t *testing.T) {
	cases := map[string]string{
		`{"a":1}`:                 `{"a":1}`,
		"```json\n{\"a\":1}\n```": `{"a":1}`,
		"prefix {\"a\":1} suffix": `{"a":1}`,
	}
	for in, want := range cases {
		if got := extractJSON(in); got != want {
			t.Errorf("extractJSON(%q) = %q, want %q", in, got, want)
		}
	}
}
