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
