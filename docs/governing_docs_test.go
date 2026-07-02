// SPDX-License-Identifier: LicenseRef-probectl-TBD

package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoverningDocsLiveInTargetRepo(t *testing.T) {
	rootDocs := map[string]string{
		"CLAUDE.md":            "Engineering reference for the probectl codebase",
		"probectl-PRD-v1.0.md": "Product Requirements Document",
	}

	for name, marker := range rootDocs {
		body, err := os.ReadFile(filepath.Join("..", name))
		if err != nil {
			t.Fatalf("governing doc %s must live in target repo root: %v", name, err)
		}
		if !strings.Contains(string(body), marker) {
			t.Fatalf("governing doc %s missing marker %q", name, marker)
		}
	}
}
