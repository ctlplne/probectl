// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"strings"
	"testing"
)

// TestMainRunsAreNeverCanceledInProgress (DPR-235): a canceled run leaves no
// verdict, and release.yml's "require green ci on the tagged sha" polls for
// `completed/success`. With `cancel-in-progress: true` on every ref, any push
// inside the ~20-minute window destroyed the run in flight — measured over the
// last 30 ci runs on main: 26 canceled, 3 failed, ZERO successes, ever. A branch
// that can never conclude can never be released.
//
// Main pushes share one non-canceling running lane and a replaceable pending
// slot. Protected full/manual runs keep independent groups even while pending.
func TestMainRunsAreNeverCanceledInProgress(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	block, ok := concurrencyBlock(ci)
	if !ok {
		t.Fatal("ci.yml has no top-level concurrency block")
	}
	value, ok := scalarKey(block, "cancel-in-progress")
	if !ok || value != "false" {
		t.Fatalf("full CI must explicitly preserve running work, not cancel-in-progress %q", value)
	}
	queue, ok := scalarKey(block, "queue")
	if !ok || queue != "single" {
		t.Fatal("main needs one replaceable pending slot after its running full CI")
	}
	// A per-SHA main group would bypass the shared running lane and start
	// every intermediate push. Runner availability/timeout failures remain
	// ordinary CI failures; later pushes must not destroy the current verdict.
	group, ok := scalarKey(block, "group")
	if !ok {
		t.Fatal("ci.yml's concurrency block declares no group")
	}
	if !strings.Contains(group, "refs/heads/main") {
		t.Errorf("concurrency group %q must distinguish the main push lane", group)
	}
	if !strings.Contains(group, "github.run_id") || !strings.Contains(group, "protected-") {
		t.Fatal("full/manual runs need their own concurrency group even while pending")
	}
}

func TestFullQualificationKeepsExactMainPinAndSecurityIndependence(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	for _, required := range []string{"workflow_dispatch:", "qualification_sha:", "required: true", "QUALIFICATION_SHA: ${{ inputs.qualification_sha }}", "python3 scripts/ci_qualification.py --selftest", "python3 scripts/ci_qualification.py", "path: artifacts/ci-qualification/"} {
		if !strings.Contains(ci, required) {
			t.Errorf("full exact-main qualification is missing %q", required)
		}
	}
	codeql := readWorkflow(t, "codeql.yml")
	block, present := concurrencyBlock(codeql)
	value, configured := scalarKey(block, "cancel-in-progress")
	group, grouped := scalarKey(block, "group")
	if !present || !configured || value != "false" || !grouped || !strings.Contains(group, "github.run_id") {
		t.Fatal("security analyses must never cancel or replace each other")
	}
	if !strings.Contains(ci, "    if: ${{ always() && !cancelled() }}") { //nolint:misspell // Exact GitHub Actions status function name.
		t.Fatal("the verification umbrella must fail closed after failed needs and release explicitly canceled runs")
	}
}

// concurrencyBlock returns the top-level concurrency mapping's text.
func concurrencyBlock(workflow string) (string, bool) {
	lines := strings.Split(workflow, "\n")
	for i, ln := range lines {
		if strings.TrimRight(ln, " ") != "concurrency:" {
			continue
		}
		var out []string
		for _, nxt := range lines[i+1:] {
			if strings.TrimSpace(nxt) == "" {
				continue
			}
			if !strings.HasPrefix(nxt, " ") {
				break
			}
			out = append(out, nxt)
		}
		return strings.Join(out, "\n"), true
	}
	return "", false
}

// scalarKey reads `key: value` out of a mapping block, ignoring comments.
func scalarKey(block, key string) (string, bool) {
	for _, ln := range strings.Split(block, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "#") || !strings.HasPrefix(t, key+":") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(t, key+":")), true
	}
	return "", false
}
