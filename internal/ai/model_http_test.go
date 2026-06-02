package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		answer := `{"root_cause":"x","confidence":"medium","findings":[{"statement":"s","citations":["E1","E42"]}]}`
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

func TestHTTPModelErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	m, _ := NewHTTPModel(HTTPModelConfig{Kind: KindOllama, Endpoint: srv.URL, Model: "m"})
	if _, err := m.Synthesize(context.Background(), SynthesisInput{Question: "q"}); err == nil {
		t.Error("non-2xx should error")
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
