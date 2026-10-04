// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestDependencyBotsCoverEveryLockfileAndDigestLocation closes SUP-16: every
// committed lockfile/manifest and every digest-pinned image location must be
// tracked by an update bot, or a stale, vulnerable dependency can ride along
// unflagged. Dependabot (.github/dependabot.yml) owns the gomod/npm/pip/
// Dockerfile/actions ecosystems; Renovate (.github/renovate.json) owns the
// Compose + Helm-values image digests Dependabot's docker manager cannot track.
// Fail-before: the pre-fix dependabot.yml had no pip (/analyzer) and no npm
// (/browser-worker) entry, so those assertions fail on an assertion.
func TestDependencyBotsCoverEveryLockfileAndDigestLocation(t *testing.T) {
	db := readRepoFile(t, ".github", "dependabot.yml")

	ecoRe := regexp.MustCompile(`(?m)^\s*-?\s*package-ecosystem:\s*"?([a-z-]+)"?`)
	dirRe := regexp.MustCompile(`(?m)^\s*directory:\s*"([^"]+)"`)
	present := map[string]bool{}
	var eco string
	for _, ln := range strings.Split(db, "\n") {
		if m := ecoRe.FindStringSubmatch(ln); m != nil {
			eco = m[1]
			continue
		}
		if m := dirRe.FindStringSubmatch(ln); m != nil && eco != "" {
			present[eco+" "+m[1]] = true
			eco = ""
		}
	}

	// Every committed lockfile/manifest location in the repo.
	required := []string{
		"gomod /",                // go.mod
		"gomod /test",            // test module
		"npm /web",               // web/package-lock.json
		"npm /browser-worker",    // browser-worker/package-lock.json (SUP-16)
		"pip /analyzer",          // analyzer/requirements*.lock + pyproject (SUP-16)
		"docker /deploy/docker",  // Dockerfile FROM pins
		"docker /browser-worker", // browser-worker Dockerfile FROM pins
		"github-actions /",       // workflow action pins
	}
	for _, r := range required {
		if !present[r] {
			have := make([]string, 0, len(present))
			for k := range present {
				have = append(have, k)
			}
			sort.Strings(have)
			t.Errorf("SUP-16: .github/dependabot.yml has no update entry for %q (have %v)", r, have)
		}
	}

	// Renovate must carry the digest updater for the Compose/Helm image pins
	// (Dependabot's docker manager tracks Dockerfile FROM, not @sha256: pins in
	// Compose YAML or Helm values).
	rv := readRepoFile(t, ".github", "renovate.json")
	for _, want := range []string{"custom.regex", "deploy/compose", "deploy/helm", "sha256:"} {
		if !strings.Contains(rv, want) {
			t.Errorf("SUP-16: .github/renovate.json digest manager must reference %q so Compose/Helm image digests are kept current", want)
		}
	}

	// SUP-16: the policy doc must be reconciled with the automation — it must
	// document the numeric patch SLAs and must NOT still claim there is no
	// update bot while dependabot.yml/renovate.json exist.
	doc := readRepoFile(t, "docs", "dependency-policy.md")
	for _, want := range []string{"Critical 7 days", "High 30 days", ".github/dependabot.yml", ".github/renovate.json"} {
		if !strings.Contains(doc, want) {
			t.Errorf("SUP-16: docs/dependency-policy.md must document %q (patch SLA + the bots)", want)
		}
	}
	if strings.Contains(doc, "there is no auto-update bot") {
		t.Errorf("SUP-16: docs/dependency-policy.md still claims 'there is no auto-update bot' while dependabot.yml/renovate.json exist")
	}
}
