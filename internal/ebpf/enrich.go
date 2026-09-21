// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Enricher adds workload/process context to a flow's endpoints in place.
type Enricher interface {
	Enrich(f *Flow)
}

// NopEnricher does nothing — the bare-host default when no metadata source is
// available. ID() then falls back to the IP, so a service map is still built.
type NopEnricher struct{}

// Enrich implements Enricher.
func (NopEnricher) Enrich(*Flow) {}

// ProcEnricher resolves a flow's source PID to a process name and container id
// by reading procfs. It is CNI-agnostic: container ids come from the cgroup
// path, which works under any CRI (docker / containerd / CRI-O) without a
// Kubernetes client. ProcRoot defaults to "/proc"; tests inject a fixture root.
type ProcEnricher struct {
	ProcRoot string
}

// NewProcEnricher returns an enricher reading the given procfs root ("" => /proc).
func NewProcEnricher(procRoot string) *ProcEnricher {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &ProcEnricher{ProcRoot: procRoot}
}

// Enrich fills Source.Process / Source.Container / Source.Workload from the
// source PID, leaving any already-set field untouched.
func (p *ProcEnricher) Enrich(f *Flow) {
	if f.Source.PID == 0 {
		return
	}
	pid := strconv.FormatUint(uint64(f.Source.PID), 10)
	if f.Source.Process == "" {
		if comm, err := os.ReadFile(filepath.Join(p.ProcRoot, pid, "comm")); err == nil {
			f.Source.Process = strings.TrimSpace(string(comm))
		}
	}
	var cgroup string
	if cg, err := os.ReadFile(filepath.Join(p.ProcRoot, pid, "cgroup")); err == nil {
		cgroup = string(cg)
	}
	if f.Source.Container == "" {
		f.Source.Container = containerIDFromCgroup(cgroup)
	}
	if f.Source.Workload == "" {
		f.Source.Workload = resolveWorkloadFromCgroup(f.Source, cgroup)
	}
}

// resolveWorkload picks the best available identity for an endpoint: a short
// container id (qualified by process when known), else the process name, else
// empty (ID() then falls back to the address).
func resolveWorkloadFromCgroup(e Endpoint, cgroup string) string {
	base := resolveProcessWorkload(e)
	if podUID := podUIDFromCgroup(cgroup); podUID != "" {
		shortPod := strings.ReplaceAll(podUID, "-", "")
		if len(shortPod) > 12 {
			shortPod = shortPod[:12]
		}
		if base != "" {
			return "k8s-pod:" + shortPod + "/" + base
		}
		return "k8s-pod:" + shortPod
	}
	return base
}

func resolveProcessWorkload(e Endpoint) string {
	if e.Container != "" {
		short := e.Container
		if len(short) > 12 {
			short = short[:12]
		}
		if e.Process != "" {
			return e.Process + "@" + short
		}
		return short
	}
	return e.Process
}

// containerIDFromCgroup extracts a container id from a /proc/<pid>/cgroup file,
// handling the common docker / containerd / CRI-O path shapes across cgroup
// v1 and v2.
func containerIDFromCgroup(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		// cgroup lines are "hierarchy:controllers:path"; we want the path.
		idx := strings.LastIndex(line, ":")
		if idx < 0 {
			continue
		}
		if id := containerIDFromPath(line[idx+1:]); id != "" {
			return id
		}
	}
	return ""
}

func containerIDFromPath(path string) string {
	seg := path
	if i := strings.LastIndex(seg, "/"); i >= 0 {
		seg = seg[i+1:]
	}
	seg = strings.TrimSuffix(seg, ".scope")
	for _, pfx := range []string{"cri-containerd-", "containerd-", "docker-", "crio-", "libpod-"} {
		seg = strings.TrimPrefix(seg, pfx)
	}
	if isHex64(seg) {
		return seg
	}
	return ""
}

func podUIDFromCgroup(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		idx := strings.LastIndex(line, ":")
		if idx < 0 {
			continue
		}
		for _, seg := range strings.Split(line[idx+1:], "/") {
			if uid := podUIDFromSegment(seg); uid != "" {
				return uid
			}
		}
	}
	return ""
}

func podUIDFromSegment(seg string) string {
	i := strings.LastIndex(seg, "pod")
	if i < 0 {
		return ""
	}
	uid := strings.TrimSuffix(seg[i+len("pod"):], ".slice")
	uid = strings.ReplaceAll(uid, "_", "-")
	if isKubernetesPodUID(uid) {
		return uid
	}
	return ""
}

func isKubernetesPodUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !isHexDigit(r) {
				return false
			}
		}
	}
	return true
}

func isHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
