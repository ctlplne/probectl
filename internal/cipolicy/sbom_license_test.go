// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestReleaseSBOMsDeclareFirstPartyLicenses closes the SBOM half of G3/D-58:
// syft writes licenseDeclared NOASSERTION for probectl's own Go module, so
// every SBOM the release publishes must pass through
// scripts/sbom_declare_licenses.sh (annotate, then check) BEFORE it is
// attested or signed. The tool's own tests (cmd/probectl-sbom-license) prove
// annotate/check over real syft output; this test proves the release cannot
// skip them. Fail-before: the pre-D-58 release.yml attested and signed syft's
// output as-is.
func TestReleaseSBOMsDeclareFirstPartyLicenses(t *testing.T) {
	rel := readWorkflow(t, "release.yml")

	order := func(what string, steps ...string) {
		t.Helper()
		last := -1
		for _, s := range steps {
			i := strings.Index(rel, s)
			if i < 0 {
				t.Errorf("%s: release.yml no longer contains %q", what, s)
				return
			}
			if i < last {
				t.Errorf("%s: %q must come after the step before it", what, s)
			}
			last = i
		}
	}
	// Image SBOMs: scan, declare, then attest.
	order("image SBOM",
		`scan --platform linux/amd64 "registry:${IMAGE_REF}" -o spdx-json=image-sbom.spdx.json`,
		`bash scripts/sbom_declare_licenses.sh image-sbom.spdx.json image "${IMAGE_REF}" linux/amd64`,
		`cosign attest --yes --type spdxjson --predicate image-sbom.spdx.json`)
	// Release SBOM over dist/: generate, declare, then attest and sign dist/*.
	order("release SBOM",
		"output-file: dist/probectl_${{ github.ref_name }}_sbom.spdx.json",
		`bash scripts/sbom_declare_licenses.sh "$sbom" dir dist`,
		"actions/attest-build-provenance@",
		"cosign sign-blob")
	if strings.Contains(rel, "upload-artifact: true") {
		t.Error("release.yml uploads sbom-action's unannotated SBOM as a workflow artifact; the signed dist/ copy is the SBOM of record")
	}

	script := readRepoFile(t, "scripts", "sbom_declare_licenses.sh")
	annotate := strings.Index(script, `"$tool" annotate`)
	check := strings.Index(script, `"$tool" check`)
	if annotate < 0 || check < annotate {
		t.Error("scripts/sbom_declare_licenses.sh must annotate the SBOM and then check it (no first-party NOASSERTION)")
	}
	if !strings.Contains(script, "REUSE_MAP_OUT=") || !strings.Contains(script, "check_reuse_licensing.sh") {
		t.Error("scripts/sbom_declare_licenses.sh must take its per-file licenses from the REUSE gate's map")
	}

	// probectl's own npm package ships in the browser-agent image; syft reads
	// its license from the manifest, so the manifest must declare it.
	var pkg struct {
		Name    string `json:"name"`
		License string `json:"license"`
	}
	if err := json.Unmarshal([]byte(readRepoFile(t, "browser-worker", "package.json")), &pkg); err != nil {
		t.Fatal(err)
	}
	if pkg.License != "BUSL-1.1" {
		t.Errorf("browser-worker/package.json (%s) declares license %q; it is BUSL-1.1 core", pkg.Name, pkg.License)
	}
}
