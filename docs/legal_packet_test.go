// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package docs

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCounselChecklistNeverMasqueradesAsApproval(t *testing.T) {
	b, err := os.ReadFile("legal/counsel-checklist.json")
	if err != nil {
		t.Fatal(err)
	}
	var checklist struct {
		Schema           string `json:"schema"`
		Authoritative    bool   `json:"authoritative"`
		FounderDecisions []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"founder_decisions"`
		CounselItems []struct {
			ID          string `json:"id"`
			Status      string `json:"status"`
			Owner       string `json:"owner"`
			Deliverable string `json:"deliverable"`
		} `json:"counsel_items"`
	}
	if err := json.Unmarshal(b, &checklist); err != nil {
		t.Fatal(err)
	}
	if checklist.Schema != "probectl-counsel-checklist/v1" || checklist.Authoritative {
		t.Fatalf("counsel checklist must remain versioned and non-authoritative: %+v", checklist)
	}
	if len(checklist.FounderDecisions) < 6 || len(checklist.CounselItems) != 12 {
		t.Fatalf("incomplete checklist: %d decisions, %d counsel items", len(checklist.FounderDecisions), len(checklist.CounselItems))
	}
	seen := make(map[string]bool)
	for _, item := range checklist.CounselItems {
		if item.ID == "" || seen[item.ID] || item.Status != "open" || item.Owner == "" || item.Deliverable == "" {
			t.Fatalf("invalid or prematurely closed counsel item: %+v", item)
		}
		seen[item.ID] = true
	}
}
