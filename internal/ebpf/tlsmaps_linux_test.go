// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build linux

package ebpf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A fake /proc, because the real one cannot be made to hold the case that
// matters: two processes from DIFFERENT container images mapping libraries with
// the same path and different inodes. That is the shape that made a correctly
// scoped capture silent (DPR-127).
func fakeProc(t *testing.T, pid string, maps string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "maps"), []byte(maps), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

const curlMaps = `aaaa0000-aaaa1000 r-xp 00000000 fd:01 100 /usr/bin/curl
ffff99800000-ffff99900000 r-xp 00000000 fd:01 1288702 /usr/lib/aarch64-linux-gnu/libssl.so.3
ffff99900000-ffff99a00000 r--p 00100000 fd:01 1288702 /usr/lib/aarch64-linux-gnu/libssl.so.3
ffff99a00000-ffff99b00000 r-xp 00000000 fd:01 555 /usr/lib/aarch64-linux-gnu/libcrypto.so.3
`

func TestMappedTLSLibrariesFindsTheLibraryTheProcessActuallyUses(t *testing.T) {
	proc := fakeProc(t, "4242", curlMaps)
	libs := mappedTLSLibrariesForPID(proc, 4242, tlsLibraryNames())
	if len(libs) != 1 {
		t.Fatalf("want exactly one TLS library (the two libssl rows are one file), got %d: %+v", len(libs), libs)
	}
	got := libs[0]
	if got.Ino != 1288702 {
		t.Errorf("inode = %d, want the one the process mapped (1288702)", got.Ino)
	}
	if got.InContainer != "/usr/lib/aarch64-linux-gnu/libssl.so.3" {
		t.Errorf("in-container path = %q", got.InContainer)
	}
	// The agent must open it THROUGH the process's root, or it reaches its own
	// filesystem and attaches to the wrong inode — which is the whole bug.
	if !strings.HasSuffix(got.Path, "/4242/root/usr/lib/aarch64-linux-gnu/libssl.so.3") {
		t.Errorf("agent path %q must go through /proc/<pid>/root", got.Path)
	}
	// libcrypto is not a TLS entry point and must not be probed.
	for _, l := range libs {
		if strings.Contains(l.InContainer, "libcrypto") {
			t.Error("libcrypto is not a TLS library for these uprobes")
		}
	}
}

// The case the lab produced: the node ships one libssl and a container brings
// another at the same path. Same path, different inode — two distinct probes.
func TestMappedTLSLibrariesDistinguishesByInodeNotPath(t *testing.T) {
	root := t.TempDir()
	for pid, ino := range map[string]string{"100": "1634783", "200": "1288702"} {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		line := "ffff99800000-ffff99900000 r-xp 00000000 fd:01 " + ino + " /usr/lib/aarch64-linux-gnu/libssl.so.3\n"
		if err := os.WriteFile(filepath.Join(dir, "maps"), []byte(line), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	libs := mappedTLSLibrariesForPIDs(root, map[uint32]struct{}{100: {}, 200: {}}, tlsLibraryNames())
	if len(libs) != 2 {
		t.Fatalf("same path, two inodes, must be two probes — got %d: %+v", len(libs), libs)
	}
}

// Forty replicas of one image are one file, so one probe.
func TestMappedTLSLibrariesDeduplicatesAcrossProcesses(t *testing.T) {
	root := t.TempDir()
	for _, pid := range []string{"1", "2", "3"} {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "maps"), []byte(curlMaps), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	libs := mappedTLSLibrariesForPIDs(root, map[uint32]struct{}{1: {}, 2: {}, 3: {}}, tlsLibraryNames())
	if len(libs) != 1 {
		t.Fatalf("three processes sharing one file must yield one probe, got %d", len(libs))
	}
}

// A process that exits between the scan and the read is the normal case on a
// moving system, not a fault.
func TestMappedTLSLibrariesIgnoresAVanishedProcess(t *testing.T) {
	if got := mappedTLSLibrariesForPID(t.TempDir(), 99999, tlsLibraryNames()); got != nil {
		t.Errorf("a process with no maps file must yield nothing, got %+v", got)
	}
}

func TestMatchesTLSLibraryAcceptsAVersionedSoname(t *testing.T) {
	names := tlsLibraryNames()
	for _, in := range []string{"libssl.so.3", "libssl.so.3.0.2", "libgnutls.so.30", "libgnutls.so.30.31.0"} {
		if !matchesTLSLibrary(in, names) {
			t.Errorf("%q should be probed", in)
		}
	}
	for _, in := range []string{"libcrypto.so.3", "libssl.so", "libc.so.6", "libsslx.so.3"} {
		if matchesTLSLibrary(in, names) {
			t.Errorf("%q should not be probed", in)
		}
	}
}

// DPR-127: a cgroup: entry is the documented way to scope another pod's
// workload, and the kernel matches those by cgroup id — so no tgid ever lands
// in the map. Their processes still have to be enumerated, or there is nothing
// to resolve a library from and the capture attaches to nothing.
func TestPidsForScopeIncludesCgroupMembers(t *testing.T) {
	cg := t.TempDir()
	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte("101\n102\n\n103\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries := []ScopeEntry{
		{Kind: scopeCgroup, Path: cg},
		{Kind: scopePID, PID: 7},
	}
	got := pidsForScope(entries, map[uint32]struct{}{7: {}})
	for _, want := range []uint32{7, 101, 102, 103} {
		if _, ok := got[want]; !ok {
			t.Errorf("pid %d missing from the scope's process set: %v", want, got)
		}
	}
	if len(got) != 4 {
		t.Errorf("want 4 processes, got %d: %v", len(got), got)
	}
}

func TestPidsInCgroupToleratesAnAbsentOrJunkFile(t *testing.T) {
	if n := len(pidsInCgroup(filepath.Join(t.TempDir(), "nope"))); n != 0 {
		t.Errorf("a missing cgroup must yield no pids, got %d", n)
	}
	cg := t.TempDir()
	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte("not-a-pid\n0\n42\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := pidsInCgroup(cg)
	if len(got) != 1 {
		t.Fatalf("junk lines and pid 0 must be skipped, got %v", got)
	}
	if _, ok := got[42]; !ok {
		t.Errorf("the one real pid must survive: %v", got)
	}
}
