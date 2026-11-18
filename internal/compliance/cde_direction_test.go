// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package compliance

import (
	"testing"
	"time"
)

func TestDirectionalControlEvidenceKeepsViolationsInTheirSelectedDirection(t *testing.T) {
	document := `name: declared-cde
zones:
  - name: outside
    cidrs: ["192.0.2.0/24"]
  - name: cde
    cidrs: ["198.51.100.0/24"]
rules:
  - id: bidirectional
    from: outside
    to: cde
    bidirectional: true
    ports: [443]
`
	policy, err := ParsePolicy([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	const tenant = "owned-cde"
	for _, check := range []struct {
		control string
		want    Verdict
	}{
		{PCIInboundNetworkControl, VerdictObservedClean},
		{PCIOutboundNetworkControl, VerdictViolation},
	} {
		t.Run(check.control, func(t *testing.T) {
			selected, err := PolicyForControl(policy, check.control, "cde")
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewTenantEngine(map[string][]Policy{tenant: {selected}})
			if err != nil {
				t.Fatal(err)
			}
			at := time.Now().UTC()
			engine.Observe(tenant, FlowObs{Src: "198.51.100.1", Dst: "192.0.2.1", DstPort: 443, At: at, Source: "flow"})
			engine.Observe(tenant, FlowObs{Src: "192.0.2.1", Dst: "198.51.100.1", DstPort: 8443, At: at, Source: "flow"})
			evidence, err := engine.Export(tenant)
			if err != nil || len(evidence.Records) != 1 || evidence.Records[0].Result.Verdict != check.want {
				t.Fatal("boundary observations crossed the requested CDE direction", evidence.Records, err)
			}
		})
	}
	if !policy.Rules[0].Bidirectional {
		t.Fatal("directional evidence mutated the reusable declared policy")
	}
	if _, err := PolicyForControl(policy, PCIInboundNetworkControl, "undeclared"); err == nil {
		t.Fatal("directional evidence inferred an undeclared CDE")
	}
}

func TestDirectionalControlEvidenceSignsTheZoneEvenWhenUnavailable(t *testing.T) {
	collected := time.Now().UTC()
	input := ControlEvidenceInput{
		TenantID: "owned-cde", Reference: PCIInboundNetworkControl, CollectedAt: collected,
		Evidence: SectionInput{Kind: SectionSegmentation, Status: StatusUnavailable, Reason: "No attested inbound observations."},
		Window:   &ControlEvidenceWindow{From: collected.Add(-time.Hour), To: collected},
	}
	if _, _, err := BuildControlEvidence(input); err == nil {
		t.Fatal("directional evidence accepted an unspecified cardholder-data zone")
	}
	input.ProtectedZone = "owned-cardholder-zone"
	manifest, attachments, err := BuildControlEvidence(input)
	if err != nil || manifest.Control == nil || manifest.Control.ProtectedZone != input.ProtectedZone ||
		len(attachments) != 0 || manifest.Sections[0].Status != StatusUnavailable {
		t.Fatal("signed unavailable evidence lost its exact observation scope", err)
	}
	input.Reference = PCISegmentationControl
	if _, _, err := BuildControlEvidence(input); err == nil {
		t.Fatal("general segmentation evidence accepted a directional zone")
	}
}
