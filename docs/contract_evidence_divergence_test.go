// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package docs

import (
	"sort"
	"testing"

	"github.com/ctlplne/probectl/internal/completeness"
)

// declaredDeliveredButPartial is the DECLARED set of buyer-facing "delivered"
// capability IDs (docs/contract/product-contract.json) whose stricter evidence
// ledger (capabilities.yaml) still records evidence_status: partial — delivered
// to buyers, but without complete real-stack proof yet.
//
// TQ-05: this divergence used to be SILENT. The buyer contract marked 52
// features + all 5 planes "delivered" and the README implied CI checked that
// against the code, while capabilities.yaml independently recorded ~42 of those
// delivered IDs as partial, and nothing cross-checked the two. Pinning the set
// here makes it visible and CI-enforced: a NEW delivered-without-complete-
// evidence capability, or one whose evidence later becomes complete, fails this
// test until the declaration — and the buyer-facing claim — is reconciled.
//
// Whether to DOWNGRADE these buyer-facing "delivered" claims to match the
// evidence, or to produce the parked real-stack proofs, is a positioning
// decision for the maintainer, tracked in
// design-partner-readiness/decisions-needed.md (D-28, TQ-05).
var declaredDeliveredButPartial = map[string]bool{
	"F1": true, "F2": true, "F3": true, "F4": true, "F5": true, "F6": true,
	"F7": true, "F8": true, "F10": true, "F11": true, "F12": true, "F13": true,
	"F14": true, "F15": true, "F16": true, "F18": true, "F19": true, "F21": true,
	"F22": true, "F25": true, "F26": true, "F27": true, "F28": true, "F30": true,
	"F31": true, "F34": true, "F36": true, "F37": true, "F38": true, "F40": true,
	"F41": true, "F42": true, "F43": true, "F44": true, "F45": true, "F46": true,
	"F47": true, "F51": true, "F52": true, "F53": true, "F55": true, "F56": true,
}

// TestDeliveredContractMatchesEvidenceLedger cross-checks the buyer-facing
// product contract against the stricter evidence ledger (TQ-05). Every
// "delivered" ID must exist in capabilities.yaml, and the delivered-but-partial
// divergence must match declaredDeliveredButPartial exactly.
func TestDeliveredContractMatchesEvidenceLedger(t *testing.T) {
	c := readContract(t)
	delivered := map[string]bool{}
	for _, f := range c.Features {
		if f.Status == "delivered" {
			for _, id := range f.IDs {
				delivered[id] = true
			}
		}
	}
	if len(delivered) == 0 {
		t.Fatal("no delivered features parsed from product-contract.json")
	}

	reg, err := completeness.LoadRegistry("../capabilities.yaml")
	if err != nil {
		t.Fatalf("load capabilities.yaml: %v", err)
	}
	ev := map[string]string{}
	for _, cap := range reg.Capabilities {
		ev[cap.ID] = cap.EffectiveEvidenceStatus()
	}

	var missing, partial []string
	for id := range delivered {
		es, ok := ev[id]
		if !ok {
			missing = append(missing, id)
			continue
		}
		if es == "partial" {
			partial = append(partial, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(partial)

	if len(missing) > 0 {
		t.Errorf("TQ-05: product-contract marks these delivered but they have NO entry in capabilities.yaml: %v", missing)
	}

	got := map[string]bool{}
	for _, id := range partial {
		got[id] = true
		if !declaredDeliveredButPartial[id] {
			t.Errorf("TQ-05: %s is delivered but evidence_status=partial and is NOT declared — reconcile the buyer claim (downgrade or prove it, D-28) or add it to declaredDeliveredButPartial", id)
		}
	}
	for id := range declaredDeliveredButPartial {
		if !got[id] {
			t.Errorf("TQ-05: %s is declared delivered-but-partial but is no longer partial in capabilities.yaml — remove it from declaredDeliveredButPartial (evidence improved)", id)
		}
	}
	t.Logf("TQ-05: %d of %d delivered capabilities are still evidence_status=partial (declared, pending real-stack proof; D-28)", len(partial), len(delivered))
}
