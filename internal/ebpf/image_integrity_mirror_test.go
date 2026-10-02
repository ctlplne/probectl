// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"strings"
	"testing"
)

// TestAgentImageIntegrityCoversMirrorsAndPinsRekor is the RTO-12 gate. Kyverno
// verifyImages only verifies image references that MATCH imageReferences;
// anything unmatched is skipped and admitted UNVERIFIED. The policy previously
// listed only `ghcr.io/ctlplne/probectl-ebpf-agent*`, so the privileged eBPF
// DaemonSet pulled from a mirror registry bypassed signature verification
// entirely — and keyless verification never pinned a transparency log. The
// older TestAgentHelmImageIntegrityAdmissionIsFailClosed checked neither, so it
// passed on the defective policy; this gate catches both, in every policy copy.
//
// (The live admission e2e — chart installs, policy Ready, unsigned/mirror image
// denied, signed digest admitted — needs a kind + Kyverno + cosign cluster and
// is parked to D-28; this is the static-policy correctness half.)
func TestAgentImageIntegrityCoversMirrorsAndPinsRekor(t *testing.T) {
	const mirrorGlob = "*/ctlplne/probectl-ebpf-agent*"
	const rekorURL = "rekor.sigstore.dev"

	// values.yaml feeds the Helm template; it must carry the mirror glob and the
	// rekor URL the template renders.
	values := readDeployContractFile(t, "deploy/helm/probectl-agent/values.yaml")
	for _, want := range []string{mirrorGlob, "rekorURL: https://" + rekorURL} {
		if !strings.Contains(values, want) {
			t.Errorf("RTO-12: agent values.yaml must carry %q so verifyImages covers mirrors / pins the tlog", want)
		}
	}

	// The Helm template must render the rekor block when rekorURL is set.
	tmpl := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/image-integrity-policy.yaml")
	for _, want := range []string{"$policy.rekorURL", "rekor:", "url: {{ $policy.rekorURL"} {
		if !strings.Contains(tmpl, want) {
			t.Errorf("RTO-12: image-integrity template must render the rekor.url pin (%q)", want)
		}
	}

	// The standalone GitOps manifest must carry both directly.
	standalone := readDeployContractFile(t, "deploy/admission/probectl-agent-image-integrity.kyverno.yaml")
	for _, want := range []string{mirrorGlob, "rekor:", rekorURL} {
		if !strings.Contains(standalone, want) {
			t.Errorf("RTO-12: standalone admission policy must carry %q (mirror coverage + pinned tlog)", want)
		}
	}
}
