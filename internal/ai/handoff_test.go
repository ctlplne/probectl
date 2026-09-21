// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderHandoffMatchesSharedGoldenContract(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "test", "fixtures", "ai-handoff")
	raw, err := os.ReadFile(filepath.Join(fixtureDir, "answer.json"))
	if err != nil {
		t.Fatal(err)
	}
	var answer Answer
	if err := json.Unmarshal(raw, &answer); err != nil {
		t.Fatal(err)
	}

	for _, locale := range []string{"en", "es", "ar"} {
		t.Run(locale, func(t *testing.T) {
			got := RenderHandoff(answer, locale)
			goldenPath := filepath.Join(fixtureDir, "handoff."+locale+".md")
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Fatalf("handoff drifted from shared %s golden", locale)
			}
		})
	}
}

func TestRenderHandoffMatchesSharedAdversarialCanonicalGolden(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "test", "fixtures", "ai-handoff")
	raw, err := os.ReadFile(filepath.Join(fixtureDir, "answer.adversarial.json"))
	if err != nil {
		t.Fatal(err)
	}
	var answer Answer
	if err := json.Unmarshal(raw, &answer); err != nil {
		t.Fatal(err)
	}

	got := RenderHandoff(answer, "en")
	goldenPath := filepath.Join(fixtureDir, "handoff.adversarial.en.md")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatal("handoff drifted from shared adversarial canonical golden")
	}
}

func TestRenderHandoffFailsClosedForInsufficientOrAmbiguousClaims(t *testing.T) {
	answer := Answer{
		ID:                   "ans-1",
		Tenant:               "tenant-a",
		Question:             "what happened?",
		RootCause:            "unresolved root must not leave the process",
		RootCauseGrounded:    true,
		RootCauseCitations:   []Citation{{EvidenceID: "duplicate"}},
		Confidence:           ConfidenceLow,
		Model:                "builtin",
		Reasoning:            ReasoningProvenance{Adapter: "builtin", Execution: ReasoningBuiltin, EgressConsent: ConsentNotRequired},
		InsufficientEvidence: true,
		Findings: []Finding{{
			Statement: "ambiguous finding must not leave the process",
			Citations: []Citation{{EvidenceID: "duplicate"}},
		}},
		Evidence: []Evidence{
			{ID: "duplicate", Domain: DomainEntities, Title: "one"},
			{ID: "duplicate", Domain: DomainEntities, Title: "two"},
		},
	}

	got := RenderHandoff(answer, "en")
	for _, forbidden := range []string{
		answer.RootCause,
		answer.Findings[0].Statement,
		"[duplicate](#evidence-",
	} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("ambiguous causal prose leaked into handoff: %q", forbidden)
		}
	}
	for _, required := range []string{
		"**Insufficient evidence:** yes",
		"Not exported:",
		"Point\\-in\\-time, non\\-authoritative",
	} {
		if !strings.Contains(got, required) {
			t.Fatalf("handoff missing fail-closed receipt %q:\n%s", required, got)
		}
	}
}

func TestRenderHandoffNormalizesLocaleAndEscapesMarkdown(t *testing.T) {
	answer := Answer{
		ID:                   "ans<script>",
		Tenant:               "tenant-a",
		Question:             "# injected heading\n> injected quote",
		Confidence:           ConfidenceLow,
		Model:                "builtin",
		Reasoning:            ReasoningProvenance{Adapter: "builtin", Execution: ReasoningBuiltin, EgressConsent: ConsentNotRequired},
		InsufficientEvidence: true,
	}
	got := RenderHandoff(answer, "ar-EG")
	for _, required := range []string{
		"lang=ar; dir=rtl",
		"\\# injected heading",
		"\\> injected quote",
		"` ans<script> `",
	} {
		if !strings.Contains(got, required) {
			t.Fatalf("Arabic handoff missing escaped/localized contract %q:\n%s", required, got)
		}
	}
}
