// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"regexp"
	"strings"
	"testing"
)

// RTO-27: the anonymous-pull smoke used to be gated on a repository variable
// nobody set, so it never ran and nobody learned that GHCR refused anonymous
// pulls. It now runs on every release, after the images and the charts are
// published, through the script the local rehearsal exercised, and it must never
// hold credentials of its own.
func TestAnonymousPullSmokeRunsOnEveryRelease(t *testing.T) {
	smoke := jobBlock(t, readWorkflow(t, "release.yml"), "anonymous-pull-smoke")
	if regexp.MustCompile(`(?m)^    if:`).MatchString(smoke) {
		t.Error("release.yml's anonymous-pull-smoke job is conditional again; it must run on every release (G1, RTO-27)")
	}
	needs := regexp.MustCompile(`(?m)^    needs: \[(.*)\]`).FindStringSubmatch(smoke)
	if needs == nil || !strings.Contains(needs[1], "images") || !strings.Contains(needs[1], "publish-chart") {
		t.Error("release.yml's anonymous-pull-smoke job must run after both the images and the charts are published (G1)")
	}
	if !strings.Contains(smoke, "scripts/release_anonymous_pull_smoke.sh") {
		t.Error("release.yml's anonymous-pull-smoke job no longer runs scripts/release_anonymous_pull_smoke.sh (G1)")
	}
	for _, credential := range []string{"packages: read", "packages: write", "docker/login-action", "registry login", "GITHUB_TOKEN"} {
		if strings.Contains(smoke, credential) {
			t.Errorf("release.yml's anonymous-pull-smoke job carries a credential (%q); an anonymous smoke must hold none (RTO-27)", credential)
		}
	}
}
