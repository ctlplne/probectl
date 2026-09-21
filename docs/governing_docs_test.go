// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoverningDocsLiveInTargetRepo(t *testing.T) {
	rootDocs := map[string]string{
		"AGENTS.md":            "Instructions for coding agents",
		"CLAUDE.md":            "Engineering reference for the probectl codebase",
		"probectl-PRD-v1.0.md": "Product Requirements Document",
		"probectl-PRD-v1.1.md": "Product Requirements Document",
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

func TestEngineeringEntryPointsNameCurrentSteeringContract(t *testing.T) {
	for _, name := range []string{"AGENTS.md", "CLAUDE.md"} {
		body, err := os.ReadFile(filepath.Join("..", name))
		if err != nil {
			t.Fatalf("read engineering entry point %s: %v", name, err)
		}
		text := string(body)
		for _, want := range []string{
			"`probectl-PRD-v1.1.md` is the current steering contract",
			"`probectl-PRD-v1.0.md` remains the detailed feature/evidence inventory",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s must preserve governing-document role %q", name, want)
			}
		}
	}
}
