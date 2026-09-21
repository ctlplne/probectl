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

// Every Go tool a workflow installs must name an exact version. A floating
// @latest/@master means the gate's behavior changes without a commit: a scanner
// can start reporting more, or less, and nothing in the repository records which
// one produced a given verdict. The repo already installs gitleaks, nfpm, vimto,
// protoc-gen-go and cyclonedx-gomod this way; this keeps it true as jobs change.
//
// DPR-269 is why it matters here: the govulncheck job used to delegate to a
// third-party action whose own nested checkout broke, so the vulnerability gate
// went red without scanning. Running tools directly, pinned, is what replaced it.
var goInstallRe = regexp.MustCompile(`go install\s+([^\s@]+)@(\S+)`)

// exactVersionRe: a semver tag, optionally with a prerelease/build suffix, or a
// pseudo-version. Anything else (latest, master, main, a bare branch) floats.
var exactVersionRe = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.\-]+)?(\+[0-9A-Za-z.\-]+)?$`)

func TestWorkflowGoInstallsPinExactVersions(t *testing.T) {
	t.Parallel()
	dir := filepath.Join("..", "..", ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read workflows: %v", err)
	}
	found := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		for _, m := range goInstallRe.FindAllStringSubmatch(string(body), -1) {
			found++
			module, version := m[1], strings.TrimSuffix(m[2], `"`)
			if !exactVersionRe.MatchString(version) {
				t.Errorf("%s installs %s@%s — a floating version changes what the gate does without a commit; pin an exact release", entry.Name(), module, version)
			}
		}
	}
	// Non-vacuity: the repo installs several tools this way. Zero matches means the
	// pattern stopped matching how workflows install things, not that all is well.
	if found < 5 {
		t.Fatalf("found only %d pinned `go install` line(s) across the workflows; the detection no longer matches them", found)
	}
	t.Logf("checked %d `go install` line(s)", found)
}
