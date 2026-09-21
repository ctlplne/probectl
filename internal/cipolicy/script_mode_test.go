// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestWorkflowInvokedScriptsAreExecutable (DPR-241): a script a workflow runs as
// `./scripts/x.sh` must be mode 100755 IN GIT, or the step dies with
// "Permission denied" and exit 126 before doing anything.
//
// This repository sets core.fileMode=false, so git ignores on-disk permission
// bits entirely: `chmod +x` changes nothing git will record, and a new script is
// committed 100644 no matter what `ls -l` says. Locally it then runs fine —
// `bash scripts/x.sh` never consults the exec bit, and the working tree's own
// mode is correct — so the break is invisible until a fresh checkout in CI
// materializes git's mode. That is exactly how DPR-236's new gate shipped
// non-executable and failed the web job on the first run that reached it.
//
// The index is the authority, not the filesystem, so this asks git rather than
// os.Stat: a filesystem check would pass locally for the same reason the bug
// survived locally.
func TestWorkflowInvokedScriptsAreExecutable(t *testing.T) {
	refs := regexp.MustCompile(`\./scripts/[A-Za-z0-9_.-]+\.sh`)
	wanted := map[string]bool{}
	for _, wf := range workflowFiles(t) {
		for _, m := range refs.FindAllString(readWorkflow(t, wf), -1) {
			wanted[strings.TrimPrefix(m, "./")] = true
		}
	}
	if len(wanted) < 5 {
		t.Fatalf("found only %d ./scripts/*.sh workflow invocations; the guard has stopped checking anything", len(wanted))
	}

	paths := make([]string, 0, len(wanted))
	for p := range wanted {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	out, err := exec.Command("git", append([]string{"-C", repoRoot(t), "ls-files", "-s", "--"}, paths...)...).Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	modes := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		// "100755 <sha> 0\t<path>"
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		modes[line[tab+1:]] = strings.Fields(line[:tab])[0]
	}

	for _, p := range paths {
		mode, tracked := modes[p]
		if !tracked {
			t.Errorf("%s is invoked as ./%s by a workflow but is not tracked by git", p, p)
			continue
		}
		if mode != "100755" {
			t.Errorf("%s is invoked as ./%s by a workflow but git records mode %s — the step will fail "+
				"with \"Permission denied\" (exit 126). Fix with: git update-index --chmod=+x %s "+
				"(core.fileMode is false here, so chmod alone does nothing git records)", p, p, mode, p)
		}
	}
}
