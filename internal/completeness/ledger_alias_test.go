// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package completeness

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLedgerUIAliasesAreVisibleAndSorted(t *testing.T) {
	registry := Registry{Capabilities: []Capability{{
		ID:    "CLM-SHARED-UI",
		Name:  "Shared UI fixture",
		Owner: "internal/fixture",
		UIAliases: map[string]string{
			"F90": "The shared operator page exposes this exact fixture workflow.",
			"F10": "The earlier feature owns the shared operator page and controls.",
		},
	}}}
	ledger := NewLedger("capabilities.yaml", registry)

	aliases := ledger.Capabilities[0].UIAliases
	if len(aliases) != 2 || aliases[0].FeatureID != "F10" || aliases[1].FeatureID != "F90" {
		t.Fatalf("UI aliases = %#v, want feature IDs sorted as F10, F90", aliases)
	}

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "ledger.json")
	htmlPath := filepath.Join(dir, "ledger.html")
	if err := WriteJSON(jsonPath, ledger); err != nil {
		t.Fatal(err)
	}
	if err := WriteHTML(htmlPath, ledger); err != nil {
		t.Fatal(err)
	}

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Ledger
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatal(err)
	}
	if got := decoded.Capabilities[0].UIAliases; len(got) != 2 || got[0].FeatureID != "F10" || got[1].FeatureID != "F90" {
		t.Fatalf("JSON UI aliases = %#v, want feature IDs sorted as F10, F90", got)
	}
	assertOrderedAliases(t, "JSON", jsonData)

	htmlData, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(htmlData, []byte("Approved UI aliases")) ||
		!bytes.Contains(htmlData, []byte("The earlier feature owns the shared operator page and controls.")) ||
		!bytes.Contains(htmlData, []byte("The shared operator page exposes this exact fixture workflow.")) {
		t.Fatalf("HTML ledger does not expose UI alias IDs and reasons")
	}
	assertOrderedAliases(t, "HTML", htmlData)
}

func assertOrderedAliases(t *testing.T, artifact string, data []byte) {
	t.Helper()
	first := bytes.Index(data, []byte("F10"))
	second := bytes.Index(data, []byte("F90"))
	if first < 0 || second < 0 || first >= second {
		t.Fatalf("%s UI aliases are not deterministically sorted: F10 index %d, F90 index %d", artifact, first, second)
	}
}
