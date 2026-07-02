// SPDX-License-Identifier: LicenseRef-probectl-TBD

package docs

import (
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
