// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"os"
	"os/exec"
	"path/filepath"
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

	assertTrackedExecutable(t, wanted, "a workflow")
}

// TestMakefileAndDocInvokedScriptsAreExecutable (DPR-301): the same rule for
// the scripts a USER runs. docs/getting-started.md opens with `make
// first-data`, whose recipe is `./scripts/first_data.sh`; that script was
// committed 100644, so the first command of the documented first hour died on
// a fresh clone with "Permission denied" (make: Error 126) before it built
// anything. The workflow guard above never saw it, because no workflow runs
// that target. The Makefile and every Markdown page a user follows are now
// scanned too.
func TestMakefileAndDocInvokedScriptsAreExecutable(t *testing.T) {
	// A leading "./" that is not the tail of "../" — a relative Markdown link
	// such as ../scripts/x.sh is a link, not an invocation.
	refs := regexp.MustCompile(`(?:^|[^A-Za-z0-9_./-])\./(scripts/[A-Za-z0-9_.-]+\.sh)`)
	root := repoRoot(t)
	sources := []string{"Makefile", "README.md", "CONTRIBUTING.md"}
	if err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".md") {
			rel, _ := filepath.Rel(root, path)
			sources = append(sources, rel)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk docs: %v", err)
	}
	wanted := map[string]bool{}
	for _, src := range sources {
		b, err := os.ReadFile(filepath.Join(root, src))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", src, err)
		}
		for _, m := range refs.FindAllStringSubmatch(string(b), -1) {
			wanted[m[1]] = true
		}
	}
	if !wanted["scripts/first_data.sh"] {
		t.Fatal("the Makefile no longer invokes ./scripts/first_data.sh; the guard has stopped checking the first-hour path")
	}
	if len(wanted) < 20 {
		t.Fatalf("found only %d ./scripts/*.sh Makefile/doc invocations; the guard has stopped checking anything", len(wanted))
	}
	assertTrackedExecutable(t, wanted, "the Makefile or a doc")
}

// assertTrackedExecutable fails for every path git does not track at mode
// 100755. The index is the authority, not the filesystem (see above).
func assertTrackedExecutable(t *testing.T, wanted map[string]bool, invoker string) {
	t.Helper()
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
			t.Errorf("%s is invoked as ./%s by %s but is not tracked by git", p, p, invoker)
			continue
		}
		if mode != "100755" {
			t.Errorf("%s is invoked as ./%s by %s but git records mode %s — the step will fail "+
				"with \"Permission denied\" (exit 126). Fix with: git update-index --chmod=+x %s "+
				"(core.fileMode is false here, so chmod alone does nothing git records)", p, p, invoker, mode, p)
		}
	}
}
