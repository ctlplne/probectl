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
	"slices"
	"strings"
	"testing"
)

// TestShippedBinaryRefusesDevAuth pins the binary half of TQ-03: the SHIPPED
// (untagged) binary cannot be run with the dev-auth bypass at all. The
// no-devauth-in-release job compiles the release binary, asserts the dev-auth
// symbol + literal are absent, proves the gate is non-vacuous against a
// devauth-tagged build, and behaviorally boots the release binary with
// PROBECTL_AUTH_MODE=dev and requires it to refuse. This gate keeps that proof
// from being dropped; TestE2EDrivesTheReleaseImageInProductionAuth pins the
// other half, the black-box e2e against the release image.
func TestShippedBinaryRefusesDevAuth(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	job := jobBlock(t, ci, "no-devauth-in-release")
	for _, want := range []string{
		"PROBECTL_AUTH_MODE=dev",        // the behavioral boot-refusal check
		"not compiled into this binary", // the exact refusal the shipped binary must emit
		"devAuthPrincipal",              // the symbol that must be ABSENT from the release binary
		"dev@probectl.local",            // the dev-principal literal that must be absent
		"go build -tags devauth",        // the non-vacuity self-test build
	} {
		if !strings.Contains(job, want) {
			t.Errorf("TQ-03: ci.yml no-devauth-in-release job must keep the shipped-binary production-auth proof %q; "+
				"without it nothing proves the binary as shipped refuses the dev-auth bypass", want)
		}
	}
}

// TestE2EDrivesTheReleaseImageInProductionAuth pins TQ-03's acceptance: a
// verify-all job builds the release image the way image-scan does (no build
// tags, the core edition), the black-box e2e runs THAT image in session auth
// against a real IdP, and nothing under test/e2e can reach the dev-auth bypass
// — `grep -E 'devauth|AUTH_MODE=dev|DEV_AUTH_ACK' test/e2e` returns nothing.
func TestE2EDrivesTheReleaseImageInProductionAuth(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	if !slices.Contains(verifyAllNeeds(t, ci), "e2e") {
		t.Error("TQ-03: ci.yml's e2e job must be in verify-all's needs; a nightly-only e2e went red for 19 nights unseen (G6)")
	}
	job := jobBlock(t, ci, "e2e")
	for _, want := range []string{
		"file: deploy/docker/Dockerfile",
		"COMPONENT=probectl-control",
		"EDITION=core",
		"load: true",
		"PROBECTL_E2E_IMAGE:",
		"run: make e2e",
	} {
		if !strings.Contains(job, want) {
			t.Errorf("TQ-03: ci.yml's e2e job must build and test the release image (%q missing)", want)
		}
	}
	for _, forbidden := range []string{"GO_TAGS", "push: true", "LICENSE_PUBKEYS_B64"} {
		if strings.Contains(job, forbidden) {
			t.Errorf("TQ-03: ci.yml's e2e job must test the image as shipped and never publish it (found %q)", forbidden)
		}
	}

	devAuth := regexp.MustCompile(`devauth|AUTH_MODE=dev|DEV_AUTH_ACK`)
	sessionAuth := regexp.MustCompile(`"PROBECTL_AUTH_MODE":\s+"session"`)
	dir := filepath.Join(repoRoot(t), "test", "e2e")
	var sawSession, sawDex, sawImage bool
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		body := string(raw)
		if loc := devAuth.FindStringIndex(body); loc != nil {
			t.Errorf("TQ-03: %s reaches the dev-auth bypass (%q); the e2e must authenticate as production does",
				path, body[loc[0]:loc[1]])
		}
		sawSession = sawSession || sessionAuth.MatchString(body)
		sawDex = sawDex || strings.Contains(body, "scripts/ci_dex.sh")
		sawImage = sawImage || strings.Contains(body, `"deploy/docker/Dockerfile"`)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sawSession || !sawDex || !sawImage {
		t.Errorf("TQ-03: test/e2e must run the release image (%t) in session auth (%t) against the real Dex (%t)",
			sawImage, sawSession, sawDex)
	}
}
