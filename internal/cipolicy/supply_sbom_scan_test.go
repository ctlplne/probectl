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

// TestSupplyChainSBOMAndScanning closes SUP-18: the release/scan supply chain
// must (1) run ONE govulncheck version everywhere — a stale v1.1.4 alongside a
// current v1.8.0 means part of CI scanned against an old vuln DB; (2) SBOM the
// SHIPPED artifacts (dist/), not the whole source tree (`path: .` pulled in web
// devDeps / the test module); (3) attest build provenance for the non-image
// release blobs; (4) actually scan the -tags ebpf build, whose dependency
// surface the default lane cannot even load.
//
// Fail-before: pre-fix the repo had v1.1.4 (ci.yml + govulncheck_packages.sh),
// SBOM `path: .`, no attest-build-provenance, and no `-tags ebpf` govulncheck.
func TestSupplyChainSBOMAndScanning(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	sec := readWorkflow(t, "security-scan.yml")
	pkgs := readRepoFile(t, "scripts", "govulncheck_packages.sh")
	rel := readWorkflow(t, "release.yml")

	// (1) One govulncheck version across every site — no stale v1.1.x.
	stale := regexp.MustCompile(`govulncheck[^\n]*v1\.1\.4|v1\.1\.4[^\n]*govulncheck|GOVULNCHECK_VERSION=v1\.1\.4`)
	for name, body := range map[string]string{"ci.yml": ci, "security-scan.yml": sec, "govulncheck_packages.sh": pkgs} {
		if stale.MatchString(body) {
			t.Errorf("SUP-18: %s still pins govulncheck v1.1.4 — align every site to the current version", name)
		}
	}
	if !strings.Contains(pkgs, "v1.8.0") {
		t.Error("SUP-18: scripts/govulncheck_packages.sh must default to the aligned govulncheck version v1.8.0")
	}

	// (2) The release SBOM scans dist/, not the source tree.
	if regexp.MustCompile(`(?m)^\s*path:\s*\.\s*$`).MatchString(rel) {
		t.Error("SUP-18: release.yml SBOM still uses `path: .` (whole source tree) — SBOM the shipped artifacts (path: dist)")
	}
	if !regexp.MustCompile(`anchore/sbom-action[\s\S]{0,200}path:\s*dist`).MatchString(rel) {
		t.Error("SUP-18: release.yml SBOM step must scan `path: dist` (the shipped artifacts)")
	}

	// (3) Build-provenance attestation for the release blobs.
	if !strings.Contains(rel, "actions/attest-build-provenance@") {
		t.Error("SUP-18: release.yml must attest build provenance for the release artifacts (actions/attest-build-provenance)")
	}

	// (4) The -tags ebpf build is govulncheck-scanned.
	if !regexp.MustCompile(`govulncheck[^\n]*-tags ebpf|-tags ebpf[^\n]*govulncheck`).MatchString(ci) {
		t.Error("SUP-18: ci.yml must run govulncheck over the -tags ebpf build (the eBPF agent's dependency surface)")
	}
}
