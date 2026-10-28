// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"encoding/json"
	"os/exec"
	"testing"

	"golang.org/x/mod/semver"
)

// The shipped-module gate rejects fixable advisories even without a reachable
// symbol. Retain the release floor for GO-2026-6860 / GO-2026-6866 so a lock
// rollback cannot reintroduce either HTML parser/renderer defect.
func TestGoNetReleaseIncludesHTMLSecurityFixes(t *testing.T) {
	cmd := exec.Command("go", "list", "-m", "-json", "golang.org/x/net")
	cmd.Dir = repoRoot(t)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("resolve effective x/net selection: %v\n%s", err, output)
	}
	var selected struct {
		Path    string
		Version string
		Replace json.RawMessage
	}
	if err := json.Unmarshal(output, &selected); err != nil {
		t.Fatal(err)
	}
	if selected.Path != "golang.org/x/net" || len(selected.Replace) != 0 {
		t.Fatal("x/net must resolve to an auditable upstream release, without a replacement")
	}
	if !semver.IsValid(selected.Version) || semver.Compare(selected.Version, "v0.62.0") < 0 {
		t.Fatalf("GO-2026-6860/6866 require x/net >= v0.62.0; selected %s", selected.Version)
	}
}
