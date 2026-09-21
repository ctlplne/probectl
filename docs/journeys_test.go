// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package docs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestProductionOperationsChaosStepIsLocalEvidenceDrill(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("journeys", "production-operations.md"))
	if err != nil {
		t.Fatalf("read production-operations journey: %v", err)
	}
	body := string(doc)
	normalized := strings.Join(strings.Fields(body), " ")
	for _, want := range []string{
		"local evidence drill",
		"`make chaos-dependency-drill`",
		"`CHAOS_DEPENDENCY_RESULT`",
		"not a served production workflow",
		"not a remote chaos API",
		"does not call the control-plane API",
		"F47 remains `none-by-design`",
	} {
		if !strings.Contains(body, want) && !strings.Contains(normalized, want) {
			t.Fatalf("production operations J6.5 must document chaos as a local evidence drill: missing %q", want)
		}
	}
}

func TestJourneyMarkdownLinksResolve(t *testing.T) {
	paths := []string{"journeys.md"}
	matches, err := filepath.Glob(filepath.Join("journeys", "*.md"))
	if err != nil {
		t.Fatalf("glob journey docs: %v", err)
	}
	paths = append(paths, matches...)

	linkRE := regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)
	for _, path := range paths {
		doc, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, match := range linkRE.FindAllStringSubmatch(string(doc), -1) {
			target := strings.TrimSpace(match[1])
			if target == "" || strings.HasPrefix(target, "#") ||
				strings.HasPrefix(target, "http://") ||
				strings.HasPrefix(target, "https://") ||
				strings.HasPrefix(target, "mailto:") {
				continue
			}
			if idx := strings.IndexByte(target, '#'); idx >= 0 {
				target = target[:idx]
			}
			if target == "" {
				continue
			}
			resolved := filepath.Clean(filepath.Join(filepath.Dir(path), target))
			if _, err := os.Stat(resolved); err != nil {
				t.Fatalf("%s links to missing local target %q resolved as %s: %v", path, match[1], resolved, err)
			}
		}
	}
}

type journeyMeasurementBaseline struct {
	Measurements []struct {
		Journey              string `json:"journey"`
		PointerInteractions  int    `json:"pointer_interactions"`
		KeyboardInteractions int    `json:"keyboard_interactions"`
		ContextBreaks        int    `json:"context_breaks"`
	} `json:"measurements"`
}

// The journey measurement baseline is the machine-readable authority for J1-J6
// interaction counts. It used to be cross-checked against a prose rubric table;
// that report was an internal assessment and no longer ships, so what remains
// checkable is the baseline's own integrity — which is where the invariant that
// actually matters lives: a single rubric cell cannot stand for both pointer and
// keyboard interaction counts, so the two must agree or the measurement is a
// guess presented as a number.
func TestJourneyMeasurementBaselineIsWellFormed(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("ux", "journey-baseline.json"))
	if err != nil {
		t.Fatalf("read journey baseline: %v", err)
	}
	var baseline journeyMeasurementBaseline
	if err := json.Unmarshal(raw, &baseline); err != nil {
		t.Fatalf("decode journey baseline: %v", err)
	}
	if len(baseline.Measurements) != 6 {
		t.Fatalf("journey baseline has %d measurements, want 6 (J1-J6)", len(baseline.Measurements))
	}
	seen := map[string]bool{}
	for _, m := range baseline.Measurements {
		if m.Journey == "" {
			t.Error("journey baseline contains an empty journey id")
			continue
		}
		if seen[m.Journey] {
			t.Errorf("journey %s appears twice in the baseline", m.Journey)
		}
		seen[m.Journey] = true
		if m.PointerInteractions != m.KeyboardInteractions {
			t.Errorf(
				"%s pointer interactions %d differ from keyboard interactions %d; one measurement cannot represent both",
				m.Journey, m.PointerInteractions, m.KeyboardInteractions,
			)
		}
		if m.PointerInteractions <= 0 {
			t.Errorf("%s records %d interactions; a journey nobody can complete is not a measurement", m.Journey, m.PointerInteractions)
		}
		if m.ContextBreaks < 0 {
			t.Errorf("%s records %d context breaks", m.Journey, m.ContextBreaks)
		}
	}
}
