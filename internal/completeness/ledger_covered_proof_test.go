// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package completeness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TQ-06 regression. The covered count the completeness-gate reports
// (WiredCells + NoneByDesignCells) used to credit a real_stack_proof cell for
// the bare EXISTENCE of its ref, so a bound proof that skipped or failed in its
// CI lane still counted as coverage. The honest count credits a real_stack_proof
// cell only when every bound proof is a PASSING proof — present in the validated
// catalog, the set of proofs that survived the no-op/profile/runner guards. This
// drives the real covered-count computation (NewLedger) through the real proven
// set (Validator.ProvenProofRefs).
//
// Non-vacuity: revert ledger.go so NewLedger ignores provenProofs and counts a
// real_stack_proof cell by ref existence, and the skipping proof is credited
// again — coveredSkipped == coveredPassing, so the "did not drop" assertion
// below fails. That is the planted defect the old gate missed and this one
// catches: an assertion difference, not a build error.
func TestLedgerCoveredCountDropsWhenBoundProofSkipsOrFails(t *testing.T) {
	root := fixtureRepo(t)
	validator, err := NewValidator(root)
	if err != nil {
		t.Fatal(err)
	}

	// The fixture proof is a real, executing proof wired into its CI lane, so it
	// is a passing proof: it appears in the validated catalog.
	proven := validator.ProvenProofRefs()
	if !proven[fixtureRealStackProofRef] {
		t.Fatalf("fixture proof %q must be a passing proof in the validated catalog; proven=%v", fixtureRealStackProofRef, proven)
	}

	registry := fixtureRegistry()
	if violations := validator.Validate(registry); len(violations) != 0 {
		t.Fatalf("baseline fixture must validate cleanly; got %d violation(s): %#v", len(violations), violations)
	}

	passing := NewLedger("capabilities.yaml", registry, proven)
	coveredPassing := passing.Summary.WiredCells + passing.Summary.NoneByDesignCells

	// Model the SAME wired proof skipping or failing in its CI lane: it drops out
	// of the set of passing proofs. The covered count must fall by exactly the
	// real_stack_proof cell, and that cell must no longer read as covered.
	skipping := map[string]bool{}
	for ref := range proven {
		if ref != fixtureRealStackProofRef {
			skipping[ref] = true
		}
	}
	skipped := NewLedger("capabilities.yaml", registry, skipping)
	coveredSkipped := skipped.Summary.WiredCells + skipped.Summary.NoneByDesignCells

	if coveredSkipped >= coveredPassing {
		t.Fatalf("covered count did not drop when the bound proof skipped/failed: passing=%d skipped=%d", coveredPassing, coveredSkipped)
	}
	if coveredPassing-coveredSkipped != 1 {
		t.Fatalf("covered count fell by %d, want exactly 1 (the unproven real_stack_proof cell): passing=%d skipped=%d", coveredPassing-coveredSkipped, coveredPassing, coveredSkipped)
	}
	if got := passing.Capabilities[0].Cells["real_stack_proof"].State; got != "wired" {
		t.Fatalf("passing real_stack_proof cell state = %q, want wired", got)
	}
	if got := skipped.Capabilities[0].Cells["real_stack_proof"].State; got == "wired" {
		t.Fatalf("skipping real_stack_proof cell must not read as wired coverage; got %q", got)
	}

	// One predicate governs both honest counts, so the delivered headline drops
	// with the proof too: the capability is claimed delivered either way, but it
	// is proven delivered only while its proof passes.
	if passing.Summary.DeliveredCapabilities != 1 || skipped.Summary.DeliveredCapabilities != 0 {
		t.Fatalf("delivered headline must drop with the proof: passing=%d skipped=%d", passing.Summary.DeliveredCapabilities, skipped.Summary.DeliveredCapabilities)
	}
	if passing.Summary.ClaimedDeliveredCapabilities != skipped.Summary.ClaimedDeliveredCapabilities {
		t.Fatalf("claimed delivery must not move with proof pass/fail: passing=%d skipped=%d", passing.Summary.ClaimedDeliveredCapabilities, skipped.Summary.ClaimedDeliveredCapabilities)
	}
}

// A bound proof that skips in its CI lane is refused entry to the validated
// catalog by the no-op guard, which is precisely why it is absent from
// ProvenProofRefs and so (per the test above) never counts as coverage. This
// closes the chain from "skips in its lane" to "not covered".
func TestSkippingBoundProofNeverEntersTheProvenCatalog(t *testing.T) {
	root := fixtureRepo(t)
	skipBody := "//go:build integration\n\npackage integration\nimport \"testing\"\nfunc TestFooRealStack(t *testing.T) { t.Skip(\"no real stack available in this lane\") }\n"
	if err := os.WriteFile(filepath.Join(root, "test", "integration", "foo_integration_test.go"), []byte(skipBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewValidator(root); err == nil {
		t.Fatalf("a skipping bound proof must be refused the proven catalog")
	} else if !strings.Contains(err.Error(), "no-op") {
		t.Fatalf("rejection must name the no-op proof; got %v", err)
	}
}
