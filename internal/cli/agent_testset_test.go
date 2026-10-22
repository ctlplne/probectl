// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"strings"
	"testing"
)

// G9: `probectl agent list` says whether each agent runs its tenant's current
// central test set, in the same words the Admin agents table uses.
func TestAgentListShowsTestSetSync(t *testing.T) {
	agents := []Agent{
		{ID: "a1", Name: "synced", Status: "online", TestSet: &AgentTestSet{AppliedVersion: 5, CurrentVersion: 5, InSync: true}},
		{ID: "a2", Name: "lagging", Status: "online", TestSet: &AgentTestSet{AppliedVersion: 3, CurrentVersion: 5}},
		{ID: "a3", Name: "nokey", Status: "online", TestSet: &AgentTestSet{CurrentVersion: 5}},
		{ID: "a4", Name: "off", Status: "online"},
	}
	var out bytes.Buffer
	printAgents(&out, agents)
	for _, want := range []string{"TESTS", "in sync (v5)", "behind (v3 of v5)", "none applied (current v5)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("agent list missing %q:\n%s", want, out.String())
		}
	}
	if got := testSetCell(agents[3]); got != "-" {
		t.Errorf("distribution off renders %q, want -", got)
	}
}
