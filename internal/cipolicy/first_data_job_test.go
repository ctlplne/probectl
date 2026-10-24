// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestFirstDataRunsOnEveryPush pins G4(a)'s follow-up: the first command
// docs/getting-started.md gives a new user is run by a verify-all job, and
// that job only passes on a result from the server-side test the script
// creates. With no job running it, the evaluation stack stayed broken unseen
// across TEN-01 and AUTHZ-31 (DPR-301..305), and the canary's own config
// probe alone would have hidden DPR-305.
func TestFirstDataRunsOnEveryPush(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	if !slices.Contains(verifyAllNeeds(t, ci), "first-data") {
		t.Error("G4(a): ci.yml's first-data job must be in verify-all's needs; the eval stack broke unseen with no job running it")
	}
	job := jobBlock(t, ci, "first-data")
	for _, want := range []string{
		"run: make first-data",
		`PROBECTL_FIRST_DATA_REQUIRE_SERVER_SIDE: "1"`,
		"if: always()",
	} {
		if !strings.Contains(job, want) {
			t.Errorf("G4(a): ci.yml's first-data job must run the documented command and require the server-side result (%q missing)", want)
		}
	}

	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "first_data.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, want := range []string{
		`require_server_side="${PROBECTL_FIRST_DATA_REQUIRE_SERVER_SIDE:-0}"`,
		`[ "$require_server_side" != 1 ] || printf '%s' "$body" | grep -q "$test_id"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("G4(a): scripts/first_data.sh must honor PROBECTL_FIRST_DATA_REQUIRE_SERVER_SIDE (%q missing)", want)
		}
	}
	guide, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "getting-started.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(guide), "make first-data") {
		t.Error("G4(a): docs/getting-started.md no longer names make first-data; point this job at the documented first command")
	}
}
