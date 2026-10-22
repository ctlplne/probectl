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

// TestAgentImageIntegrityCoversMirrorsAndPinsRekor is the RTO-12 static gate.
// Kyverno only verifies image references that MATCH the policy's references
// (ImageValidatingPolicy matchImageReferences, formerly ClusterPolicy
// imageReferences); anything unmatched is skipped and admitted UNVERIFIED. The
// policy once listed only `ghcr.io/ctlplne/probectl-ebpf-agent*`, then fixed
// globs that still missed a mirror with a different path; the chart now DERIVES
// its reference from image.repository (so whatever the DaemonSet pulls is what
// the policy verifies), matches it against the Docker-normalized reference too
// (an ImageValidatingPolicy glob sees only the raw string), and pins the
// transparency log.
//
// The live half — two-step install, unsigned / other-key / tag-only / mirror
// images denied at admission, signed digests admitted, Kyverno down refuses —
// is scripts/kyverno_admission_smoke.sh on a kind + Kyverno cluster (ci.yml
// job kyverno-admission).
func TestAgentImageIntegrityCoversMirrorsAndPinsRekor(t *testing.T) {
	const mirrorGlob = "*/ctlplne/probectl-ebpf-agent*"
	const rekorURL = "rekor.sigstore.dev"

	values := readDeployContractFile(t, "deploy/helm/probectl-agent/values.yaml")
	for _, want := range []string{mirrorGlob, "rekorURL: https://" + rekorURL, "additionalImageReferences:"} {
		if !strings.Contains(values, want) {
			t.Errorf("RTO-12: agent values.yaml must carry %q so verifyImages covers mirrors / pins the tlog", want)
		}
	}

	// The template derives the reference from image.repository and refuses a
	// repository Kyverno would normalize away from it (no explicit registry).
	tmpl := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/image-integrity-policy.yaml")
	helpers := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/_helpers.tpl")
	for _, want := range []string{
		`$repo := .Values.image.repository`,
		"must be a lowercase repository with an explicit registry host",
		`include "probectl-agent.imageIntegrityRendered"`,
	} {
		if !strings.Contains(tmpl, want) {
			t.Errorf("RTO-12: image-integrity template must derive matchImageReferences from image.repository (%q)", want)
		}
	}
	for _, want := range []string{`printf "%s*" .Values.image.repository`} {
		if !strings.Contains(helpers, want) {
			t.Errorf("RTO-12: image-integrity template must derive imageReferences from image.repository (%q)", want)
		}
	}
	for _, want := range []string{"$policy.rekorURL", "ctlog:", "url: {{ $policy.rekorURL"} {
		if !strings.Contains(helpers, want) {
			t.Errorf("RTO-12: image-integrity spec must render the ctlog.url (Rekor) pin (%q)", want)
		}
	}
	for _, want := range []string{
		"- glob: {{ . | quote }}",
		`include "probectl-agent.imageIntegrityRefMatch"`,
		"'docker.io/' + (ref.contains('/') ? '' : 'library/') + ref",
	} {
		if !strings.Contains(helpers, want) {
			t.Errorf("RTO-12: image-integrity spec must match the derived patterns on raw AND normalized references (%q)", want)
		}
	}

	// The standalone GitOps manifest must carry both directly.
	standalone := readDeployContractFile(t, "deploy/admission/probectl-agent-image-integrity.kyverno.yaml")
	for _, want := range []string{mirrorGlob, "ctlog:", rekorURL, "'docker.io/' +"} {
		if !strings.Contains(standalone, want) {
			t.Errorf("RTO-12: standalone admission policy must carry %q (mirror coverage + pinned tlog)", want)
		}
	}
}
