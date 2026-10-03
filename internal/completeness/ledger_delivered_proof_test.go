// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package completeness

import "testing"

// PLAT-11 regression. The old ledger credited "delivered" from the status
// string alone, so a capability declared delivered with only an acknowledged
// gap (no real-stack proof) inflated the delivered headline — a pure stub
// passed the gate's delivered accounting. The honest headline counts a
// capability as delivered only when it carries a passing real-stack proof (a
// wired real_stack_proof cell, which Validate has already resolved against the
// proof catalog before a ledger renders).
//
// Non-vacuity: revert ledger.go's provenRealStack gate and DeliveredCapabilities
// becomes 2 (the stub is counted), so the `== 1` assertion below fails — that is
// the planted defect the old gate missed and this one catches.
func TestLedgerDeliveredHeadlineCountsOnlyProvenRealStackProofs(t *testing.T) {
	registry := Registry{
		Schema:        RegistrySchema,
		SourceCatalog: "docs/claims/release-catalog.json",
		Capabilities: []Capability{
			{
				ID: "F-PROVEN", Name: "Proven delivery", Status: "delivered", Owner: "fixture/owner",
				RealStackProof: Cell{Refs: []string{"test:test/integration/foo_integration_test.go#TestFooRealStack"}},
			},
			{
				// The stub: claims delivery but has no real-stack proof, only an
				// acknowledged gap. It must NOT count toward proven delivery.
				ID: "F-STUB", Name: "Claimed, unproven", Status: "delivered", Owner: "fixture/owner",
				EvidenceStatus: "partial",
				RealStackProof: Cell{Gap: "No real-service execution receipt exists for this capability yet; delivery is acknowledged as unproven."},
			},
		},
	}

	// F-PROVEN's proof is in the proven set (it passed its lane guards), so the
	// ledger credits it; F-STUB binds no proof, so it never does.
	ledger := NewLedger("capabilities.yaml", registry, fixtureProvenProofs())

	// The naive, string-only count the OLD ledger produced.
	naive := 0
	for _, capability := range registry.Capabilities {
		if capability.Status == "delivered" {
			naive++
		}
	}
	if naive != 2 {
		t.Fatalf("fixture setup: expected 2 status-delivered rows, got %d", naive)
	}

	if ledger.Summary.ClaimedDeliveredCapabilities != 2 {
		t.Fatalf("claimed_delivered_capabilities = %d, want 2 (both rows declare status delivered)", ledger.Summary.ClaimedDeliveredCapabilities)
	}
	if ledger.Summary.DeliveredCapabilities != 1 {
		t.Fatalf("delivered_capabilities = %d, want 1 (only the row with a passing real-stack proof)", ledger.Summary.DeliveredCapabilities)
	}

	// The honest headline must equal the number of capabilities with a passing
	// (wired) real-stack proof, and must be strictly below the naive count the
	// stub inflated.
	proven := 0
	for _, capability := range registry.Capabilities {
		if len(capability.RealStackProof.Refs) > 0 {
			proven++
		}
	}
	if ledger.Summary.DeliveredCapabilities != proven {
		t.Fatalf("delivered_capabilities = %d, want %d (count of capabilities with a passing real-stack proof)", ledger.Summary.DeliveredCapabilities, proven)
	}
	if ledger.Summary.DeliveredCapabilities >= naive {
		t.Fatalf("delivered headline (%d) must exclude the unproven stub, so it must be below the %d status-delivered rows", ledger.Summary.DeliveredCapabilities, naive)
	}
}

// TestValidatorRejectsRealStackProofOnNonDeliveredCapability proves the strict
// gate refuses a real_stack_proof — a passing real-stack proof — declared on a
// capability that is not delivered. A proof is the one thing that credits
// delivery, so a non-delivered row carrying one is a stub dressing an unshipped
// capability as proven. The real repository binds every proof to a delivered
// capability, so this strengthening leaves it green.
func TestValidatorRejectsRealStackProofOnNonDeliveredCapability(t *testing.T) {
	root := fixtureRepo(t)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}

	// Baseline: the fixture (F1 delivered, proof wired) is accepted.
	if violations := validator.Validate(fixtureRegistry()); len(violations) != 0 {
		t.Fatalf("baseline fixture must validate cleanly; got %d violation(s): %#v", len(violations), violations)
	}

	// Flip the proven capability to a non-delivered status while keeping its
	// wired proof: the gate must refuse it.
	registry := fixtureRegistry()
	registry.Capabilities[0].Status = "future"
	violations := validator.Validate(registry)
	if !containsViolation(violations, "F1", "real_stack_proof", "proof-requires-delivered") {
		t.Fatalf("expected proof-requires-delivered violation on the non-delivered capability; got %#v", violations)
	}
}
