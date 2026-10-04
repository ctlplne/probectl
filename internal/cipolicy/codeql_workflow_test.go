// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCodeQLAdvancedWorkflowIsCommitted closes the SUP-13 CodeQL half (and the
// DPR-245 root cause): CodeQL must run as ADVANCED setup — a committed workflow —
// so the analyzed language list lives under version control. When it lived only
// in repo settings, product analysis (Go/JS-TS/Python) silently stopped for 79
// days and no diff could show it. This asserts the workflow exists, analyzes
// every language the staleness gate requires (plus actions), runs on
// pull_request + schedule, uses the security-extended suite (go/clear-text-
// logging, go/zipslip), uploads SARIF, and pins the CodeQL action by SHA.
//
// Fail-before: with no .github/workflows/codeql.yml the first assertion fires.
func TestCodeQLAdvancedWorkflowIsCommitted(t *testing.T) {
	path := filepath.Join(repoRoot(t), ".github", "workflows", "codeql.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("SUP-13/DPR-245: .github/workflows/codeql.yml must exist so the analyzed language list is version-controlled (advanced setup), not hidden in repo settings: %v", err)
	}
	wf := string(raw)

	// Every language scripts/check_codeql_coverage.sh REQUIRES must be analyzed
	// by the committed workflow — the two must not drift apart.
	for _, lang := range requiredCodeQLLanguages(t) {
		if !regexp.MustCompile(`(?m)^\s*-?\s*`+regexp.QuoteMeta(lang)+`\b`).MatchString(wf) &&
			!strings.Contains(wf, lang) {
			t.Errorf("codeql.yml must analyze the required product language %q (coverage gate requires it)", lang)
		}
	}
	// `actions` is analyzed too (the one language that kept running — now explicit).
	if !strings.Contains(wf, "actions") {
		t.Errorf("codeql.yml should also analyze the workflows themselves (actions)")
	}

	for _, want := range []string{
		"pull_request",                  // runs on PRs
		"schedule",                      // and on a cadence the staleness gate passes
		"security-extended",             // includes go/clear-text-logging + go/zipslip
		"github/codeql-action/init@",    // SHA-pinned (checked by action-pins gate)
		"github/codeql-action/analyze@", // uploads results
		"security-events: write",        // SARIF upload permission, per-job
		"persist-credentials: false",    // SUP-04
	} {
		if !strings.Contains(wf, want) {
			t.Errorf("codeql.yml must contain %q", want)
		}
	}

	// The CodeQL action must be pinned to a 40-hex commit SHA, never a tag.
	pinned := regexp.MustCompile(`github/codeql-action/\w+@[0-9a-f]{40}`)
	if !pinned.MatchString(wf) {
		t.Errorf("codeql.yml must pin github/codeql-action to a full 40-hex commit SHA")
	}

	// Least privilege (SUP-04): no workflow-level write authority. The only
	// write is per-job security-events:write; the top-level permissions block
	// must be contents: read.
	top := regexp.MustCompile(`(?m)^permissions:\n(?:[ \t]+.*\n)+`)
	if block := top.FindString(wf); block == "" || strings.Contains(block, "write") {
		t.Errorf("codeql.yml workflow-level permissions must be read-only (got block: %q)", block)
	}
}

// requiredCodeQLLanguages parses REQUIRED_LANGUAGES from check_codeql_coverage.sh
// so this gate and that script cannot drift.
func requiredCodeQLLanguages(t *testing.T) []string {
	t.Helper()
	script := readRepoFile(t, "scripts", "check_codeql_coverage.sh")
	m := regexp.MustCompile(`REQUIRED_LANGUAGES=\(([^)]*)\)`).FindStringSubmatch(script)
	if m == nil {
		t.Fatal("could not find REQUIRED_LANGUAGES in check_codeql_coverage.sh")
	}
	langs := strings.Fields(m[1])
	if len(langs) < 3 {
		t.Fatalf("REQUIRED_LANGUAGES looks wrong: %v", langs)
	}
	return langs
}
