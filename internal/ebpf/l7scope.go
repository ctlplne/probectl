// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Process-scope allowlist for TLS-plaintext capture (EBPF-001 / RED-003).
//
// Uprobes on shared TLS libraries fire for EVERY process that maps them, so
// capture must be scoped to explicitly opted-in workloads. l7_capture_scope is
// that opt-in: a list of entries, each one of
//
//	pid:<n>          one process (exact tgid)
//	exe:/abs/path    every process whose /proc/<pid>/exe resolves to the path
//	                 (re-resolved periodically — restarts/new workers stay in
//	                 scope, exited PIDs are removed)
//	cgroup:/abs/path a cgroup v2 directory (its kernel cgroup id) — the unit of
//	                 container/pod scoping: a container IS a cgroup, so
//	                 "container label" scoping resolves here (e.g.
//	                 /sys/fs/cgroup/kubepods.slice/...pod<uid>.slice)
//
// The kernel program checks the resulting maps BEFORE copying a single byte
// (bpf/sslsniff.bpf.c scoped()); empty maps match nothing, so the default is
// capture-off even when attached. The allowlist is the THIRD consent gate:
// enable flag + tenant consent (U-003) + explicit workload scope.

// Scope entry kinds.
const (
	scopePID    = "pid"
	scopeExe    = "exe"
	scopeCgroup = "cgroup"
)

// ScopeEntry is one parsed l7_capture_scope element.
type ScopeEntry struct {
	Kind string // pid | exe | cgroup
	PID  uint32 // pid:
	Path string // exe: | cgroup: (absolute)
}

// ParseScopeEntries validates and parses l7_capture_scope. It fails closed:
// any malformed entry is a config error (refuse start, don't silently widen
// or narrow capture).
func ParseScopeEntries(raw []string) ([]ScopeEntry, error) {
	out := make([]ScopeEntry, 0, len(raw))
	for _, r := range raw {
		kind, val, ok := strings.Cut(strings.TrimSpace(r), ":")
		if !ok || val == "" {
			return nil, fmt.Errorf("ebpf: l7_capture_scope entry %q: want pid:<n>, exe:/abs/path or cgroup:/abs/path", r)
		}
		switch kind {
		case scopePID:
			n, err := strconv.ParseUint(val, 10, 32)
			if err != nil || n == 0 {
				return nil, fmt.Errorf("ebpf: l7_capture_scope entry %q: pid must be a positive integer", r)
			}
			out = append(out, ScopeEntry{Kind: scopePID, PID: uint32(n)})
		case scopeExe, scopeCgroup:
			if !filepath.IsAbs(val) {
				return nil, fmt.Errorf("ebpf: l7_capture_scope entry %q: path must be absolute", r)
			}
			out = append(out, ScopeEntry{Kind: kind, Path: filepath.Clean(val)})
		default:
			return nil, fmt.Errorf("ebpf: l7_capture_scope entry %q: unknown kind %q (pid|exe|cgroup)", r, kind)
		}
	}
	return out, nil
}

// resolveScope materializes the allowlist into the two kernel-map key sets:
// tgids (pid: entries + exe: matches under procRoot) and cgroup ids (cgroup:
// entries). exe: entries that currently match no process are NOT an error —
// the workload may start later; the refresher picks it up. A cgroup: path
// that does not exist IS an error (the opt-in names something that isn't
// there — fail closed rather than silently capture nothing... or the wrong
// thing after a typo).
func resolveScope(entries []ScopeEntry, procRoot string) (map[uint32]struct{}, map[uint64]struct{}, error) {
	tgids := make(map[uint32]struct{})
	cgroups := make(map[uint64]struct{})
	for _, e := range entries {
		switch e.Kind {
		case scopePID:
			tgids[e.PID] = struct{}{}
		case scopeExe:
			for _, pid := range resolveExePIDs(procRoot, e.Path) {
				tgids[pid] = struct{}{}
			}
		case scopeCgroup:
			id, err := cgroupID(e.Path)
			if err != nil {
				return nil, nil, fmt.Errorf("ebpf: l7_capture_scope cgroup %q: %w", e.Path, err)
			}
			cgroups[id] = struct{}{}
		}
	}
	return tgids, cgroups, nil
}

// resolveExePIDs scans procRoot for processes whose exe symlink resolves to
// exePath. Unreadable entries are skipped (processes we can't see can't be
// opted in).
func resolveExePIDs(procRoot, exePath string) []uint32 {
	var out []uint32
	dirs, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	for _, d := range dirs {
		pid, err := strconv.ParseUint(d.Name(), 10, 32)
		if err != nil || pid == 0 {
			continue // not a process dir
		}
		target, err := os.Readlink(filepath.Join(procRoot, d.Name(), "exe"))
		if err != nil {
			continue
		}
		// A replaced-on-disk binary reads "/path (deleted)" — still the
		// opted-in executable.
		target = strings.TrimSuffix(target, " (deleted)")
		if target == exePath {
			out = append(out, uint32(pid))
		}
	}
	return out
}

// cgroupID returns the kernel cgroup id for a cgroup v2 directory — the
// inode number of the cgroupfs dir, which is exactly what
// bpf_get_current_cgroup_id() reports for member processes.
func cgroupID(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if !fi.IsDir() {
		return 0, fmt.Errorf("not a cgroup directory")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("no inode information")
	}
	return st.Ino, nil
}
