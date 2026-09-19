// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
// So the rule is narrow and mechanical: ci.yml may cancel in progress, but never
// unconditionally — the expression has to exclude main and tags. Canceling on PR
// branches is the point of the setting and stays.
func TestMainRunsAreNeverCanceledInProgress(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	block, ok := concurrencyBlock(ci)
	if !ok {
		t.Fatal("ci.yml has no top-level concurrency block")
	}
	value, ok := scalarKey(block, "cancel-in-progress")
	if !ok {
		// No key at all means the default (false): main is safe.
		return
	}
	if value == "true" {
		t.Fatal("ci.yml cancels in-progress runs on EVERY ref including main — a canceled run " +
			"leaves no conclusion for release.yml's require-green-ci to read (DPR-235). Guard the " +
			"expression on github.ref instead.")
	}
	for _, want := range []string{"refs/heads/main", "refs/tags/"} {
		if !strings.Contains(value, want) {
			t.Errorf("cancel-in-progress expression %q must exempt %q", value, want)
		}
	}

	// DPR-242: not canceling is only half of it. With one group per REF, a main
	// run that never CONCLUDES blocks every later main run at `pending` — and
	// ebpf-kernel-matrix (6.6-arm64) never concludes, because its runner does not
	// exist (D-13). That happened: a push stayed pending until the previous run was
	// canceled by hand, which trades an automatic cancellation for a manual one.
	// Keying main on the commit means a stuck run is stuck alone.
	group, ok := scalarKey(block, "group")
	if !ok {
		t.Fatal("ci.yml's concurrency block declares no group")
	}
	if !strings.Contains(group, "github.sha") {
		t.Errorf("concurrency group %q must key main on github.sha, not on the ref alone: a main run "+
			"that cannot conclude would otherwise hold every later run at pending (DPR-242)", group)
	}
	if !strings.Contains(group, "refs/heads/main") {
		t.Errorf("concurrency group %q must name refs/heads/main, so branches keep one group per ref "+
			"and keep the coalescing that cancel-in-progress exists for", group)
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
