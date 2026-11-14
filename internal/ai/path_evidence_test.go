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
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPathEvidenceSelectorCannotFallBackToOtherSources(t *testing.T) {
	for _, id := range []string{"", "foreign-or-stale", "00000000-0000-4000-8000-000000000001"} {
		queries := (HeuristicPlanner{}).Plan(Question{Text: "Explain routing, events, topology and errors for api.example.com", Subject: map[string]string{
			"path_test_id": id, "target": "192.0.2.1", "node": "unrelated", "incident_id": "unrelated",
		}})
		if len(queries) != 1 || queries[0].Domain != DomainMetrics {
			t.Fatal("explicit path selector widened the source domains", id, queries)
		}
		if selected, exists := queries[0].Selector["path_test_id"]; !exists || selected != id {
			t.Fatal("explicit empty or foreign path selector was dropped")
		}
	}
}

func TestPathEvidenceCompleteRemotePromptAndCurrentDispatch(t *testing.T) {
	var prompts []string
	socket := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || len(request.Messages) != 2 {
			t.Error("incomplete model request", err)
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		prompts = append(prompts, request.Messages[1].Content)
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `{"root_cause":"observed only","confidence":"low","insufficient_evidence":true}`}}}})
	}))
	t.Cleanup(socket.Close)
	model := &HTTPModel{kind: KindOpenAI, endpoint: socket.URL, client: socket.Client(), remote: true, redact: DefaultRedaction}
	// Validated numeric metadata uses the same JSON escaping as the closed
	// source serializer. Source addresses and arbitrary text stay untrusted.
	pack := json.RawMessage(`{"items":[{"ip":"192.0.2.1","note":"alice@example.com","value":"\u0039\u0030\u0030\u0037\u0031\u0039\u0039\u0032\u0035\u0034\u0037\u0034\u0030\u0039\u0039\u0033"}],"late":"LAST_COMPLETE_RESPONDER"}`)
	input := SynthesisInput{Question: "Explain 192.0.2.1", Evidence: []Evidence{{ID: "E1", Fields: Row{"path_health": pack, "private_unregistered_field": "NEVER_SEND_THIS"}}}}
	prepared, err := prepareStructuredPrompt(input, true, DefaultRedaction, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	var original struct {
		Items []struct{ Value string }
		Late  string
	}
	if err := json.Unmarshal(prepared.Evidence[0].Fields["path_health"].(json.RawMessage), &original); err != nil || len(original.Items) != 1 || original.Items[0].Value != "9007199254740993" || original.Late != "LAST_COMPLETE_RESPONDER" {
		t.Fatal("redaction changed exact original metadata or lost the complete document", err)
	}
	if _, err := model.Synthesize(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	if len(prompts) != 1 || !strings.Contains(prompts[0], "LAST_COMPLETE_RESPONDER") || strings.Contains(prompts[0], "192.0.2.1") || strings.Contains(prompts[0], "alice@example.com") || strings.Contains(prompts[0], "NEVER_SEND_THIS") {
		t.Fatal("structured prompt was shortened or bypassed source redaction")
	}
	if !strings.Contains(string(input.Evidence[0].Fields["path_health"].(json.RawMessage)), "alice@example.com") {
		t.Fatal("remote masking mutated the original cited evidence")
	}
	for _, malformed := range []any{json.RawMessage(`{"items":`), map[string]any{"items": "unregistered shape"}} {
		input.Evidence[0].Fields["path_health"] = malformed
		if _, err := model.Synthesize(t.Context(), input); err == nil || len(prompts) != 1 {
			t.Fatal("invalid complete source document reached the remote model")
		}
	}
	input.Evidence[0].Fields["path_health"] = pack
	withdrawn := errors.New("source authority withdrawn")
	ctx := WithCurrentEvidence(t.Context(), func(context.Context) error { return withdrawn })
	if _, err := model.Synthesize(ctx, input); !errors.Is(err, withdrawn) || len(prompts) != 1 {
		t.Fatal("withdrawn current authority reached the remote model", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := CheckCurrentEvidence(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled source check succeeded", err)
	}
}

func TestPathEvidenceCacheIncludesCompleteOriginalDocument(t *testing.T) {
	first := SynthesisInput{Question: "Explain path errors", Evidence: []Evidence{{Title: "Same complete summary", Fields: Row{"path_health": json.RawMessage(`{"original":"9007199254740993","receipt":"a"}`)}}}}
	second := SynthesisInput{Question: first.Question, Evidence: []Evidence{{Title: first.Evidence[0].Title, Fields: Row{"path_health": json.RawMessage(`{"original":"9007199254740994","receipt":"b"}`)}}}}
	if synthKey(t.Context(), "model", first) == synthKey(t.Context(), "model", second) {
		t.Fatal("changed original source observations reused the synthesis cache key")
	}
}

func TestPathEvidenceAuthorityIsRecheckedAfterSynthesis(t *testing.T) {
	withdrawn := errors.New("source changed during synthesis")
	var changed bool
	model := citingModel{build: func(in SynthesisInput) Synthesis {
		changed = true
		return Synthesis{RootCause: "observed path errors", Confidence: ConfidenceLow, RootCauseCitations: []Citation{{EvidenceID: in.Evidence[0].ID}}}
	}}
	ctx := WithCurrentEvidence(t.Context(), func(context.Context) error {
		if changed {
			return withdrawn
		}
		return nil
	})
	engine := engineWith(fixtureSource{metrics: []Row{{"metric": "path_errors", "title": "observed path errors"}}})
	analyzer := NewAnalyzer(engine, WithModel(model))
	if _, err := analyzer.Analyze(ctx, principal("tenant-a", PermMetricsRead), Question{Text: "Explain path errors", Subject: map[string]string{"path_test_id": "owned"}}); !errors.Is(err, withdrawn) {
		t.Fatal("changed source authority published synthesized evidence", err)
	}
}
