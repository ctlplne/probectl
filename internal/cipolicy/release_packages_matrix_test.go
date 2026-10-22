// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"regexp"
	"testing"
)

// v0.6.5's ebpf-agent package leg failed, the matrix's default fail-fast
// cancelled seven of the other legs, and the release went out with 12 of its 20
// packages while the air-gap bundle requires all 20. Each package leg must stand
// on its own, and its name must say which architecture failed.
func TestPackagesMatrixDoesNotFailFast(t *testing.T) {
	packages := jobBlock(t, readWorkflow(t, "release.yml"), "packages")
	if !regexp.MustCompile(`(?m)^\s+fail-fast:\s*false\s*$`).MatchString(packages) {
		t.Error("release.yml's packages matrix does not set `fail-fast: false`, so one failing leg cancels " +
			"the others and the release ships a partial package set (G1)")
	}
	if !regexp.MustCompile(`name: .*\$\{\{ matrix\.agent \}\}.*\$\{\{ matrix\.arch \}\}`).MatchString(packages) {
		t.Error("release.yml's packages job name does not carry both the agent and the arch, so a failed " +
			"leg does not say which package is missing (G1)")
	}
}
