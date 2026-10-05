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

// TestDeliveredContractMatchesEvidenceLedger enforces the TQ-05 invariant: a
// capability the buyer-facing product contract (docs/contract/product-contract.json)
// marks "delivered" MUST have complete real-stack evidence in the stricter
// evidence ledger (capabilities.yaml). A "delivered" ID whose evidence ledger
// still records evidence_status: partial is an over-claim and fails here.
//
// History (D-28, TQ-05, decided 2026-10-05 — DOWNGRADE to evidence): this
// divergence was once SILENT (the contract marked 52 features "delivered" while
// capabilities.yaml independently recorded ~42 of them partial, and nothing
// cross-checked the two), then made VISIBLE as a pinned declared-set. Shankar
// chose to reconcile by DOWNGRADING the buyer claims rather than parking them
// behind real-stack proofs, so the 42 delivered-but-partial features are now
// status:"partial" in the contract and the gate is the hard invariant with no
// allowlist: a new over-claim — a "delivered" feature whose evidence is only
// partial — fails here until the claim is downgraded or the proof produced.
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
	if len(partial) > 0 {
		t.Errorf("TQ-05: these capabilities are marked \"delivered\" in the buyer-facing product contract but their evidence ledger records evidence_status=partial — a \"delivered\" claim must have complete real-stack evidence; downgrade the claim to status:\"partial\" in docs/contract/product-contract.json or produce the proof (D-28): %v", partial)
	}
	t.Logf("TQ-05: %d delivered capabilities, all with complete real-stack evidence (no delivered-but-partial over-claims)", len(delivered))
}
