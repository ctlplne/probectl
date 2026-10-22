// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/store"
)

// G9: the fleet view compares each agent's applied central test-set version
// with the tenant's current one; it says nothing when distribution is off and
// nothing for a bus collector, which runs no synthetic tests.
func TestFleetTestSetComparison(t *testing.T) {
	views := []fleetAgentView{
		{Agent: store.Agent{ID: "synced", TestSetVersion: 4}},
		{Agent: store.Agent{ID: "behind", TestSetVersion: 2}},
		{Agent: store.Agent{ID: "none"}},
		{Agent: store.Agent{ID: "flow", Capabilities: []string{"collector"}}},
	}
	applyFleetTestSet(views, nil)
	for _, v := range views {
		if v.TestSet != nil {
			t.Fatalf("%s: test_set present with distribution off", v.ID)
		}
	}
	current := uint64(4)
	applyFleetTestSet(views, &current)
	want := map[string]*fleetTestSet{
		"synced": {AppliedVersion: 4, CurrentVersion: 4, InSync: true},
		"behind": {AppliedVersion: 2, CurrentVersion: 4},
		"none":   {AppliedVersion: 0, CurrentVersion: 4},
		"flow":   nil,
	}
	for _, v := range views {
		w := want[v.ID]
		if (w == nil) != (v.TestSet == nil) || (w != nil && *w != *v.TestSet) {
			t.Errorf("%s: test_set = %+v, want %+v", v.ID, v.TestSet, w)
		}
	}
	raw, err := json.Marshal(views[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"test_set":{"applied_version":4,"current_version":4,"in_sync":true}`) {
		t.Fatalf("wire shape: %s", raw)
	}
	if strings.Contains(string(raw), "TestSetVersion") {
		t.Fatalf("the raw registry column leaked onto the wire: %s", raw)
	}
}
