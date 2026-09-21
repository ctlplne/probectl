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

const verifyArtifactsPath = "ops/verify-artifacts.md"

// coverageHeading opens the one section that states what the published releases
// actually hold, as opposed to what the release workflow is able to produce.
const coverageHeading = "## What each published release carries"

var docVersionLiteral = regexp.MustCompile(`v[0-9]+\.[0-9]+(?:\.[0-9]+)?`)

// DPR-252: this page is where an operator establishes trust before running
// anything, and every version it named was one the verification could not
// possibly succeed against — TAG=v0.1.0 for binaries (that release ships no
// .sig/.pem at all), a probectl-control_v0.6.4 binary from a release that was
// never published, TAG=v0.2.0 for a chart (not a tag, and no release has ever
// published a chart), and an image tag whose registry copy carries no cosign
// signature. The page now records what is actually published, and every version
// it mentions has to be accounted for there — so a future example cannot name a
// release without saying what that release ships.
func TestVerificationPageAccountsForEveryVersionItNames(t *testing.T) {
	doc := readVerifyArtifacts(t)
	coverage := coverageSection(t, doc)

	seen := map[string]bool{}
	for _, literal := range docVersionLiteral.FindAllString(doc, -1) {
		if seen[literal] {
			continue
		}
		seen[literal] = true
		if !strings.Contains(coverage, literal) {
			t.Errorf("%s names %s but %q does not account for it; a version the page cannot say is published must not appear in a verification recipe",
				verifyArtifactsPath, literal, coverageHeading)
		}
	}
	if len(seen) == 0 {
		t.Fatalf("%s names no release at all; the coverage table cannot be checked", verifyArtifactsPath)
	}
}

// The copy-paste block is the first thing an operator runs. Pointing it at a
// release the page itself records as unsigned is the exact defect DPR-252 found,
// and it is invisible until someone downloads a 404.
func TestBinaryVerificationExampleUsesASignedRelease(t *testing.T) {
	doc := readVerifyArtifacts(t)
	coverage := coverageSection(t, doc)

	example := regexp.MustCompile(`(?m)^TAG=(v[0-9]+\.[0-9]+\.[0-9]+)`).FindStringSubmatch(doc)
	if example == nil {
		t.Fatalf("%s has no concrete TAG=vX.Y.Z binary example to check", verifyArtifactsPath)
	}
	tag := example[1]

	var row string
	for _, line := range strings.Split(coverage, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "|") && strings.Contains(line, tag) {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatalf("the binary example uses %s but %q has no row for it", tag, coverageHeading)
	}
	if !strings.Contains(row, "cosign-signed") {
		t.Errorf("the binary verification example uses %s, which the page records as not cosign-signed:\n%s",
			tag, strings.TrimSpace(row))
	}
}

func readVerifyArtifacts(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(verifyArtifactsPath)
	if err != nil {
		t.Fatalf("read %s: %v", verifyArtifactsPath, err)
	}
	return string(data)
}

func coverageSection(t *testing.T, doc string) string {
	t.Helper()
	start := strings.Index(doc, coverageHeading)
	if start < 0 {
		t.Fatalf("%s no longer has a %q section, so nothing records what is actually published",
			verifyArtifactsPath, coverageHeading)
	}
	rest := doc[start+len(coverageHeading):]
	if end := strings.Index(rest, "\n## "); end >= 0 {
		return rest[:end]
	}
	return rest
}
