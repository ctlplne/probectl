// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCLIAIAskHandoffUsesOneAskAndMatchesSharedContract(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "test", "fixtures", "ai-handoff")
	answer, err := os.ReadFile(filepath.Join(fixtureDir, "answer.json"))
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/ai/ask" {
			http.NotFound(w, r)
			return
		}
		requests.Add(1)
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body["question"] != "Why is checkout slow?" {
			t.Errorf("question = %#v", body["question"])
		}
		if _, exists := body["tenant_id"]; exists {
			t.Errorf("client tried to select tenant in body: %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(answer)
	}))
	t.Cleanup(server.Close)

	for _, locale := range []string{"en", "es", "ar"} {
		t.Run(locale, func(t *testing.T) {
			before := requests.Load()
			out, errs, code := runWithEnv(t, server, map[string]string{
				"PROBECTL_LOCALE": locale,
			}, "ai", "ask", "--handoff", "--body", `{"question":"Why is checkout slow?"}`)
			if code != 0 {
				t.Fatalf("exit = %d, stderr=%s", code, errs)
			}
			if delta := requests.Load() - before; delta != 1 {
				t.Fatalf("Ask requests = %d, want exactly 1", delta)
			}
			golden, err := os.ReadFile(filepath.Join(fixtureDir, "handoff."+locale+".md"))
			if err != nil {
				t.Fatal(err)
			}
			if out != string(golden) {
				t.Fatalf("CLI %s handoff drifted from shared contract", locale)
			}
		})
	}
}

func TestCLIAIAskHandoffRejectsInvalidCombinationsBeforeRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing body", args: []string{"ai", "ask", "--handoff"}, want: "requires --body"},
		{name: "JSON conflict", args: []string{"--json", "ai", "ask", "--handoff", "--body", `{"question":"x"}`}, want: "cannot be combined with --json"},
		{name: "query conflict", args: []string{"ai", "ask", "--handoff", "--body", `{"question":"x"}`, "--query", "x=y"}, want: "cannot be combined with --query"},
		{name: "invalid JSON", args: []string{"ai", "ask", "--handoff", "--body", `{`}, want: "invalid --body"},
		{name: "non-object", args: []string{"ai", "ask", "--handoff", "--body", `["x"]`}, want: "must be one JSON object"},
		{name: "missing question", args: []string{"ai", "ask", "--handoff", "--body", `{"subject":{}}`}, want: "requires a non-empty question"},
		{name: "unexpected", args: []string{"ai", "ask", "--handoff", "--body", `{"question":"x"}`, "extra"}, want: "unexpected arguments"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(test.args, func(key string) string {
				if key == "PROBECTL_API_URL" {
					return server.URL
				}
				return ""
			}, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("exit = %d, stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("stderr missing %q:\n%s", test.want, stderr.String())
			}
		})
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("invalid handoff invocations made %d request(s), want 0", got)
	}
}

func TestCLIAIAskHandoffLocalizesValidation(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	for _, test := range []struct {
		locale string
		want   string
	}{
		{locale: "es-MX", want: "requiere --body"},
		{locale: "ar-EG", want: "يتطلب --handoff"},
	} {
		_, errs, code := runWithEnv(t, server, map[string]string{
			"PROBECTL_LOCALE": test.locale,
		}, "ai", "ask", "--handoff")
		if code != 2 || !strings.Contains(errs, test.want) {
			t.Fatalf("%s exit=%d stderr=%s", test.locale, code, errs)
		}
	}
}
