// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// EBPF-001/RED-003: the scope allowlist parser fails closed — any malformed
// entry refuses the whole config rather than silently widening or narrowing
// what gets captured.
func TestScopeParseEntries(t *testing.T) {
	good := []string{"pid:1234", " exe:/usr/sbin/nginx ", "cgroup:/sys/fs/cgroup/app.slice"}
	entries, err := ParseScopeEntries(good)
	if err != nil {
		t.Fatalf("valid entries rejected: %v", err)
	}
	if len(entries) != 3 || entries[0].PID != 1234 || entries[1].Path != "/usr/sbin/nginx" || entries[2].Kind != scopeCgroup {
		t.Fatalf("parsed wrong: %+v", entries)
	}

	bad := map[string]string{
		"nginx":            "want pid:",    // no kind
		"pid:":             "want pid:",    // empty value
		"pid:abc":          "positive",     // non-numeric
		"pid:0":            "positive",     // zero pid
		"pid:-4":           "positive",     // negative
		"exe:nginx":        "absolute",     // relative path
		"cgroup:app.slice": "absolute",     // relative path
		"container:web":    "unknown kind", // labels resolve via cgroup paths
		"all:everything":   "unknown kind", // host-wide is not expressible
		"exe:":             "want pid:",    // empty path
	}
	for entry, wantErr := range bad {
		if _, err := ParseScopeEntries([]string{entry}); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("entry %q: want error containing %q, got %v", entry, wantErr, err)
		}
	}

	if entries, err := ParseScopeEntries(nil); err != nil || len(entries) != 0 {
		t.Fatalf("empty scope parses to empty (the gate refuses it separately): %v %v", entries, err)
	}
}

// exe: entries resolve to the PIDs whose /proc/<pid>/exe points at the
// binary — including replaced-on-disk binaries ("(deleted)" suffix) — and
// nothing else.
func TestScopeResolveExePIDs(t *testing.T) {
	proc := t.TempDir()
	mk := func(pid, target string) {
		dir := filepath.Join(proc, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	mk("100", "/usr/sbin/nginx")
	mk("200", "/usr/sbin/nginx (deleted)") // upgraded on disk, still nginx
	mk("300", "/usr/bin/redis-server")
	mk("400", "/usr/sbin/nginx")
	if err := os.MkdirAll(filepath.Join(proc, "irq"), 0o755); err != nil { // non-pid dir
		t.Fatal(err)
	}
	mk("500", "/usr/sbin/nginx-helper") // prefix, NOT a match

	pids := resolveExePIDs(proc, "/usr/sbin/nginx")
	got := map[uint32]bool{}
	for _, p := range pids {
		got[p] = true
	}
	if len(got) != 3 || !got[100] || !got[200] || !got[400] {
		t.Fatalf("want exactly {100,200,400}, got %v", pids)
	}
}

// The full resolution: pid: passes through, exe: scans proc, cgroup: takes
// the directory's inode (== bpf_get_current_cgroup_id for cgroup v2). A
// cgroup path that does not exist is an ERROR (a typo'd opt-in must not
// silently capture nothing/the wrong thing).
func TestScopeResolve(t *testing.T) {
	proc := t.TempDir()
	dir := filepath.Join(proc, "77")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/opt/app", filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	cg := t.TempDir()

	entries, err := ParseScopeEntries([]string{"pid:9001", "exe:/opt/app", "cgroup:" + cg})
	if err != nil {
		t.Fatal(err)
	}
	tgids, cgroups, err := resolveScope(entries, proc)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tgids[9001]; !ok {
		t.Fatal("pid: entry must resolve to its tgid")
	}
	if _, ok := tgids[77]; !ok {
		t.Fatal("exe: entry must resolve matching procs")
	}
	wantID, err := cgroupID(cg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cgroups[wantID]; !ok || len(cgroups) != 1 {
		t.Fatalf("cgroup: entry must resolve to the dir inode %d, got %v", wantID, cgroups)
	}

	// Missing cgroup → hard error.
	entries, _ = ParseScopeEntries([]string{"cgroup:" + filepath.Join(cg, "nope")})
	if _, _, err := resolveScope(entries, proc); err == nil {
		t.Fatal("nonexistent cgroup path must fail closed")
	}

	// exe: matching nothing is NOT an error (workload may start later).
	entries, _ = ParseScopeEntries([]string{"exe:/not/running"})
	tgids, _, err = resolveScope(entries, proc)
	if err != nil || len(tgids) != 0 {
		t.Fatalf("unmatched exe: must resolve empty without error: %v %v", tgids, err)
	}
}

// cgroupID on a file (not a directory) refuses — scope must name the cgroup
// dir, not a control file inside it.
func TestScopeCgroupIDRequiresDirectory(t *testing.T) {
	f := filepath.Join(t.TempDir(), "cgroup.procs")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cgroupID(f); err == nil {
		t.Fatal("file must not pass as a cgroup directory")
	}
}

// D-63 #2: without CAP_SYS_PTRACE an exe: entry cannot see other users'
// processes, so L7 refuses it instead of capturing a silently partial set.
func TestScopeExeRequiresPtrace(t *testing.T) {
	cases := []struct {
		name      string
		raw       []string
		canPtrace bool
		wantErr   bool
	}{
		{"non-root unit: pid and cgroup", []string{"pid:42", "cgroup:/sys/fs/cgroup/app.slice"}, false, false},
		{"non-root unit: exe refused", []string{"pid:42", "exe:/usr/sbin/nginx"}, false, true},
		{"ptrace granted (root, Helm D-02a): exe allowed", []string{"exe:/usr/sbin/nginx"}, true, false},
		{"ptrace granted: mixed", []string{"pid:1", "exe:/usr/bin/app", "cgroup:/sys/fs/cgroup/x"}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries, err := ParseScopeEntries(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			err = checkScopePrivilege(entries, tc.canPtrace)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkScopePrivilege(%v, ptrace=%v) = %v, wantErr %v", tc.raw, tc.canPtrace, err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "pid:<n> or cgroup:") {
				t.Errorf("refusal does not tell the operator what to use instead: %v", err)
			}
		})
	}
}

// The live L7 source applies the check before it loads anything (D-63 #2);
// the source is linux+ebpf only, so the wiring is asserted on the file.
func TestLiveL7SourceChecksScopePrivilege(t *testing.T) {
	b, err := os.ReadFile("source_live_l7_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "checkScopePrivilege(scope, effectiveCaps().has(capSysPtrace))") {
		t.Fatal("newLiveL7Source no longer refuses exe: scope entries without CAP_SYS_PTRACE (D-63 #2)")
	}
}
