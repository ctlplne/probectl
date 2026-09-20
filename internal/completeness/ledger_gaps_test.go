// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package completeness

import "testing"

// DPR-251: the strict release gate refused v0.6.4 with a bare count, so the one
// artifact an operator gets from a blocked release named no blocking row. Gaps
// is that list, and it has to stay complete and deterministically ordered or
// the refusal goes back to being unactionable.
func TestLedgerGapsNameEveryBlockingRowInSpineOrder(t *testing.T) {
	registry := Registry{Capabilities: []Capability{
		{
			ID:    "CLM-SECOND-ROW",
			Name:  "Second fixture row",
			Owner: "internal/fixture",
			// Deliberately out of spine order in the source: ui (index 4)
			// precedes docs (index 5), so an alphabetical sort would swap them.
			Docs: Cell{Gap: "The fixture docs receipt is deliberately absent for this test."},
			UI:   Cell{Gap: "The fixture UI receipt is deliberately absent for this test."},
		},
		{
			ID:     "CLM-FIRST-ROW",
			Name:   "First fixture row",
			Owner:  "internal/other",
			Engine: Cell{Refs: []string{"file:internal/completeness"}},
			CLI:    Cell{NoneByDesign: "This fixture capability is deliberately not exposed on the command line."},
			RealStackProof: Cell{
				Gap: "The fixture real-stack receipt is deliberately absent for this test.",
			},
		},
	}}

	ledger := NewLedger("capabilities.yaml", registry)
	gaps := ledger.Gaps()

	if len(gaps) != ledger.Summary.GapCells {
		t.Fatalf("Gaps() returned %d rows, want Summary.GapCells = %d", len(gaps), ledger.Summary.GapCells)
	}
	want := []LedgerGap{
		{Capability: "CLM-SECOND-ROW", Name: "Second fixture row", Cell: "ui", Owner: "internal/fixture",
			Reason: "The fixture UI receipt is deliberately absent for this test."},
		{Capability: "CLM-SECOND-ROW", Name: "Second fixture row", Cell: "docs", Owner: "internal/fixture",
			Reason: "The fixture docs receipt is deliberately absent for this test."},
		{Capability: "CLM-FIRST-ROW", Name: "First fixture row", Cell: "real_stack_proof", Owner: "internal/other",
			Reason: "The fixture real-stack receipt is deliberately absent for this test."},
	}
	if len(gaps) != len(want) {
		t.Fatalf("Gaps() = %#v, want %d rows", gaps, len(want))
	}
	for i := range want {
		if gaps[i] != want[i] {
			t.Errorf("Gaps()[%d] = %#v, want %#v", i, gaps[i], want[i])
		}
	}
}

// A cell that carries no disposition at all renders as "missing" rather than
// "gap"; the registry validator rejects it, so it must not be reported here as
// an acknowledged gap and quietly reclassified as governed work.
func TestLedgerGapsExcludeUndispositionedCells(t *testing.T) {
	registry := Registry{Capabilities: []Capability{{
		ID:    "CLM-UNDISPOSITIONED",
		Name:  "Undispositioned fixture row",
		Owner: "internal/fixture",
	}}}
	ledger := NewLedger("capabilities.yaml", registry)
	if got := ledger.Gaps(); len(got) != 0 {
		t.Fatalf("Gaps() = %#v, want no acknowledged gaps for undispositioned cells", got)
	}
	if ledger.Summary.GapCells != 0 {
		t.Fatalf("Summary.GapCells = %d, want 0", ledger.Summary.GapCells)
	}
}
