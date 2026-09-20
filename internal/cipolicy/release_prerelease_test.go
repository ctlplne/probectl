// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cipolicy

import (
	"regexp"
	"strings"
	"testing"
)

// Decision D-15 (2026-09-20) let a 0.x tag publish while the capability ledger
// still records acknowledged gaps, because docs/quality/completeness.md reserves
// the strict gate for a FINAL release and release.yml was applying it to every
// tag — v0.6.4 cleared all three entry gates and published nothing while three
// publish jobs went on rotting unrun.
//
// That decision is only honest while two things hold: the release says out loud
// that it carries gaps, and no tag outside 0.x can use the allowance. The second
// is behavior and is proven by the planted self-test in
// scripts/release_completeness_verdict.sh, which `make completeness-gate` runs.
// What is pinned here is the wiring that self-test cannot see — that the tested
// script is the one release.yml actually calls, and that its verdict reaches the
// release page.
func TestGappedReleasesArePublishedAsPrereleases(t *testing.T) {
	release := readWorkflow(t, "release.yml")

	gate := jobBlock(t, release, "completeness-release-gate")
	if !strings.Contains(gate, "scripts/release_completeness_verdict.sh") {
		t.Error("release.yml's capability-ledger job no longer calls scripts/release_completeness_verdict.sh, " +
			"so the release rule that actually runs is not the one the planted self-test covers (D-15)")
	}
	if strings.Contains(gate, "continue-on-error") {
		t.Error("release.yml's capability-ledger job carries continue-on-error — that is an untested bypass " +
			"of the whole gate, not the 0.x allowance D-15 granted")
	}
	for _, output := range []string{"gaps:", "prerelease:"} {
		if !strings.Contains(gate, output) {
			t.Errorf("release.yml's capability-ledger job no longer publishes the %q output, so a release "+
				"cannot state the gap count it ships with", strings.TrimSuffix(output, ":"))
		}
	}

	// A step that runs the strict gate directly would be a second, untested
	// reading of the same verdict. Mentioning the command in a release note is
	// fine; invoking it is not.
	invokes := regexp.MustCompile(`(?m)^\s*(?:run:\s*|\s+)make completeness-release-gate\b`)
	if loc := invokes.FindString(release); loc != "" {
		t.Errorf("release.yml invokes `make completeness-release-gate` directly (%q); the verdict has one "+
			"reader, scripts/release_completeness_verdict.sh, so both directions stay tested",
			strings.TrimSpace(loc))
	}

	// A pre-release that moves `latest` is recommended to everyone who pulls
	// without a tag, which is the opposite of what D-15 traded away.
	//
	// DPR-257: the assertion that used to live here checked only that the gated
	// `type=raw,value=latest` entry was present, and it PASSED while v0.6.5
	// published `latest` on all eleven components. docker/metadata-action has two
	// independent routes to that tag and the tags list is only one of them: the
	// `flavor` input defaults to `latest=auto`, which adds it for any semver tag
	// push no matter what the tags list says. So both routes are checked here,
	// and the flavor one first, because it is the one that fires by default.
	images := jobBlock(t, release, "images")
	if !regexp.MustCompile(`(?m)^\s*latest=false\s*$`).MatchString(images) {
		t.Error("release.yml's images job does not pin `flavor: latest=false`, so metadata-action's " +
			"default `latest=auto` adds `latest` for every semver tag push regardless of the tags " +
			"list — a 0.x pre-release carrying acknowledged gaps becomes the default image pull " +
			"(D-15, DPR-257)")
	}
	for _, line := range strings.Split(images, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "type=") || !strings.Contains(trimmed, "latest") {
			continue
		}
		if !strings.Contains(trimmed, "needs.completeness-release-gate.outputs.prerelease") {
			t.Errorf("release.yml tags `latest` from an entry that is not gated on the capability "+
				"ledger: %q (D-15, DPR-257)", trimmed)
		}
	}

	binaries := jobBlock(t, release, "binaries")
	if !strings.Contains(binaries, "prerelease: ${{ needs.completeness-release-gate.outputs.prerelease == 'true' }}") {
		t.Error("the GitHub release is no longer flagged from the capability-ledger gate's prerelease output — " +
			"a build carrying acknowledged gaps would publish as a full release (D-15)")
	}
	if !strings.Contains(binaries, "body_path:") {
		t.Error("the GitHub release no longer carries a body_path, so the gap count never reaches the " +
			"release page a consumer reads (D-15)")
	}
}

// jobBlock returns one job's YAML: from its two-space key to the next one.
func jobBlock(t *testing.T, workflow, job string) string {
	t.Helper()
	header := "\n  " + job + ":\n"
	start := strings.Index(workflow, header)
	if start < 0 {
		t.Fatalf("release.yml has no %q job", job)
	}
	rest := workflow[start+len(header):]
	next := regexp.MustCompile(`(?m)^  [a-z0-9][a-z0-9-]*:$`).FindStringIndex(rest)
	if next == nil {
		return rest
	}
	return rest[:next[0]]
}
