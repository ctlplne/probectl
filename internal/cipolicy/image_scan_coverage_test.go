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

// TestEveryBuiltImageIsScanned closes SUP-01: every image the build-images job
// builds must also be vuln-scanned by the image-scan job. Before the fix,
// build-images built 12 images while image-scan trivy-scanned only
// probectl-control — eleven shipped images went unscanned, and nothing caught
// it. This asserts set(build-images components) ⊆ set(image-scan components), so
// adding a published image without a scan fails CI.
//
// Fail-before: with image-scan covering only probectl-control, every other
// build-images component is reported missing.
func TestEveryBuiltImageIsScanned(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	built := matrixComponents(t, ci, "build-images")
	scanned := matrixComponents(t, ci, "image-scan")

	if len(built) < 10 {
		t.Fatalf("SUP-01: found only %d build-images components (%v) — the parser likely broke", len(built), built)
	}
	scanSet := map[string]bool{}
	for _, c := range scanned {
		scanSet[c] = true
	}
	var missing []string
	for _, c := range built {
		if !scanSet[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("SUP-01: these built images are NOT vuln-scanned by image-scan: %v (built=%v scanned=%v)", missing, built, scanned)
	}
}

// matrixComponents extracts the `component:` values from the matrix of one job
// block in a workflow file.
func matrixComponents(t *testing.T, wf, job string) []string {
	t.Helper()
	lines := strings.Split(wf, "\n")
	jobHead := regexp.MustCompile(`^  [A-Za-z0-9_-]+:\s*$`)
	comp := regexp.MustCompile(`component:\s*([A-Za-z0-9_-]+)`)
	start := -1
	for i, ln := range lines {
		if ln == "  "+job+":" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("job %q not found in workflow", job)
	}
	var out []string
	seen := map[string]bool{}
	for i := start + 1; i < len(lines); i++ {
		if jobHead.MatchString(lines[i]) { // next top-level job ends this block
			break
		}
		// Only count matrix include entries (list items), not build-args refs.
		if !strings.Contains(lines[i], "- {") && !strings.Contains(strings.TrimSpace(lines[i]), "- component:") {
			continue
		}
		if m := comp.FindStringSubmatch(lines[i]); m != nil && !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}
