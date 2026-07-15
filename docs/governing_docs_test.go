// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
