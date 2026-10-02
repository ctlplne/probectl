// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package docs

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestAirgapAndSignatureDocsAreConsistent is the INV-01 / RTO-25 / RTO-27 gate.
// Two doc-consistency defects let the operator docs promise artifacts the
// release record contradicts:
//   - verify-artifacts.md's table + prose said v0.6.5 images were "the first
//     images ever signed" while its own Images section said "No image in GHCR
//     carries that signature yet" — a direct contradiction.
//   - air-gap.md hardcoded version=0.6.5 and claimed "each release publishes" a
//     bundle, but v0.6.5 shipped NO air-gap bundle (its chart job failed).
//
// This pins the reconciliation so neither regresses.
func TestAirgapAndSignatureDocsAreConsistent(t *testing.T) {
	verify := readOpsDoc(t, "ops/verify-artifacts.md")
	verifyFlat := strings.Join(strings.Fields(verify), " ") // collapse line wraps
	// The overclaim must be gone, and the conservative statement present.
	for _, banned := range []string{
		"the first images ever signed",
		"first this project has ever signed",
	} {
		if strings.Contains(verifyFlat, banned) {
			t.Errorf("INV-01/RTO-27: verify-artifacts.md still claims images are signed (%q) while its Images section says none are — reconcile to one statement", banned)
		}
	}
	if !strings.Contains(verifyFlat, "No image in GHCR carries that signature yet") {
		t.Error("INV-01/RTO-27: verify-artifacts.md lost the authoritative image-signature statement")
	}

	airgap := readOpsDoc(t, "ops/air-gap.md")
	// No hardcoded release version in a shell assignment: operators must set it
	// to a release that actually carries the bundle.
	if m := regexp.MustCompile(`(?m)^\s*version=[0-9]`).FindString(airgap); m != "" {
		t.Errorf("INV-01/RTO-25: air-gap.md hardcodes a release version (%q); parameterize it (version=\"${version:?...}\") since not every release carries the bundle", strings.TrimSpace(m))
	}
	if strings.Contains(airgap, "charts/probectl-0.6.5.tgz") {
		t.Error("INV-01/RTO-25: air-gap.md hardcodes charts/probectl-0.6.5.tgz; use charts/probectl-${version}.tgz")
	}
	if !strings.Contains(airgap, `version="${version:?`) {
		t.Error("INV-01/RTO-25: air-gap.md must parameterize the bundle version with a required-variable guard")
	}
	// The doc must not claim EVERY release carries the bundle.
	if strings.Contains(airgap, "Each release publishes one signed tarball") {
		t.Error("INV-01/RTO-25: air-gap.md still claims every release publishes a bundle; the bundle depends on all upstream jobs succeeding")
	}
}

func readOpsDoc(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}
