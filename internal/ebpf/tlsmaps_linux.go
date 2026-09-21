// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build linux

package ebpf

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Finding the TLS library a SCOPED PROCESS actually uses, rather than the one
// the node happens to ship.
//
// DPR-127, second half. A uprobe attaches to an INODE. The agent discovered the
// node's libssl and attached there, but a container brings its own copy from its
// image: on the lab, the node's libssl.so.3 is inode 1634783 and the scoped
// workload's curl calls inode 1288702. Different files, so the probe can never
// fire — which is why a consented, correctly scoped capture reported
// l7_attach_failures:0, l7_scope_sync_failures:0, and l7_calls:0 forever.
//
// hostPID (D-02) is what makes the fix possible: with the node's processes in
// view, /proc/<pid>/maps says exactly which library each scoped process mapped,
// and /proc/<pid>/root reaches that file from the agent's own mount namespace.

// mappedTLSLibrary is one TLS library a scoped process has mapped, identified by
// the inode the kernel will key the uprobe on.
type mappedTLSLibrary struct {
	// Path is where the AGENT can open it: /proc/<pid>/root/<path-in-container>.
	Path string
	// InContainer is the path as the process itself sees it, for logs.
	InContainer string
	// Dev and Ino identify the file. Two processes sharing an image share these,
	// so the agent attaches once rather than once per process.
	Dev string
	Ino uint64
}

// tlsLibraryNames is every basename worth probing, from the discovery lists.
func tlsLibraryNames() []string {
	names := make([]string, 0, len(libsslNames)+len(libgnutlsNames))
	names = append(names, libsslNames...)
	names = append(names, libgnutlsNames...)
	return names
}

// mappedTLSLibrariesForPID reads /proc/<pid>/maps and returns the distinct TLS
// libraries that process has mapped.
//
// An unreadable or vanished process is not an error: a scope is resolved
// repeatedly against a moving system, and a process that exited between the
// scan and the read is the normal case, not a fault.
func mappedTLSLibrariesForPID(procRoot string, pid uint32, names []string) []mappedTLSLibrary {
	f, err := os.Open(filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10), "maps"))
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var out []mappedTLSLibrary
	sc := bufio.NewScanner(f)
	// A mapping line is long but bounded; the default 64KiB buffer is plenty and
	// a pathological line is skipped rather than grown into.
	for sc.Scan() {
		// address perms offset dev inode path
		//   ffff…-ffff… r-xp 00000000 fd:01 1288702 /usr/lib/…/libssl.so.3
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		path := strings.Join(fields[5:], " ")
		if !matchesTLSLibrary(filepath.Base(path), names) {
			continue
		}
		dev := fields[3]
		ino, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil || ino == 0 {
			continue
		}
		key := dev + ":" + strconv.FormatUint(ino, 10)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, mappedTLSLibrary{
			// /proc/<pid>/root is the process's mount namespace seen from here.
			// It is the only way to reach a file that exists solely inside a
			// container image.
			Path:        filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10), "root", path),
			InContainer: path,
			Dev:         dev,
			Ino:         ino,
		})
	}
	return out
}

// matchesTLSLibrary reports whether a mapped basename is a TLS library worth
// probing. A real mapping is often versioned beyond the names we know
// ("libssl.so.3.0.2"), so a known name is a prefix match, not an equality.
func matchesTLSLibrary(base string, names []string) bool {
	for _, n := range names {
		if base == n || strings.HasPrefix(base, n+".") {
			return true
		}
	}
	return false
}

// mappedTLSLibrariesForPIDs collects the distinct TLS libraries across every
// scoped process, so the agent attaches once per FILE rather than once per
// process — a deployment of forty replicas from one image is one inode.
func mappedTLSLibrariesForPIDs(procRoot string, pids map[uint32]struct{}, names []string) []mappedTLSLibrary {
	seen := make(map[string]struct{})
	var out []mappedTLSLibrary
	for pid := range pids {
		for _, lib := range mappedTLSLibrariesForPID(procRoot, pid, names) {
			key := lib.Dev + ":" + strconv.FormatUint(lib.Ino, 10)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, lib)
		}
	}
	return out
}

// pidsInCgroup lists the processes in a cgroup v2 directory.
//
// DPR-127: this is how a cgroup: scope entry — the documented unit of
// container/pod scoping, because a container IS a cgroup — yields the processes
// whose TLS libraries need probing. Measured on the lab: reading cgroup.procs
// and /proc/<pid>/maps both work under the agent's documented
// CAP_BPF + CAP_PERFMON, while /proc/<pid>/exe does NOT (it is ptrace-gated, and
// a capability-dropped agent is not a superset of the target's capabilities).
// So cgroup scoping reaches another pod's workload at the privilege already
// granted, and exe: scoping across containers would need CAP_SYS_PTRACE.
func pidsInCgroup(cgroupPath string) map[uint32]struct{} {
	out := map[uint32]struct{}{}
	f, err := os.Open(filepath.Join(cgroupPath, "cgroup.procs"))
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		pid, err := strconv.ParseUint(strings.TrimSpace(sc.Text()), 10, 32)
		if err != nil || pid == 0 {
			continue
		}
		out[uint32(pid)] = struct{}{}
	}
	return out
}

// pidsForScope returns every process the scope names: the tgids already
// resolved, plus the members of each scoped cgroup.
func pidsForScope(entries []ScopeEntry, tgids map[uint32]struct{}) map[uint32]struct{} {
	all := make(map[uint32]struct{}, len(tgids))
	for pid := range tgids {
		all[pid] = struct{}{}
	}
	for _, e := range entries {
		if e.Kind != scopeCgroup {
			continue
		}
		for pid := range pidsInCgroup(e.Path) {
			all[pid] = struct{}{}
		}
	}
	return all
}
