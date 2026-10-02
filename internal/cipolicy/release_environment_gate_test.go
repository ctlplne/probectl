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

// TestReleasePublishJobsAreEnvironmentGated is the SUP-03 (code-side) gate.
// SUP-03: a semver tag drives publishing with no second human in the loop — the
// release trusts any tag. The in-repo half of the fix is that every job with a
// PUBLISH side effect (push images to GHCR, create the GitHub release, push the
// Helm chart, sign+attach deb/rpm packages) runs under the `release` GitHub
// Environment, so once that Environment is configured with required reviewers
// (repo settings, D-24) a release pauses for approval even after the tag push.
// This test pins the declaration so it cannot be silently dropped; the
// reviewers themselves are a server-side setting this cannot assert.
func TestReleasePublishJobsAreEnvironmentGated(t *testing.T) {
	release := readWorkflow(t, "release.yml")
	publishers := []string{"images", "binaries", "publish-chart", "packages"}
	for _, job := range publishers {
		block := jobBlock(t, release, job)
		if !strings.Contains(block, "environment: release") {
			t.Errorf("SUP-03: release.yml publishing job %q must declare `environment: release` so the "+
				"publish requires environment approval (D-24); without it a tag publishes with no second human", job)
		}
	}
}
