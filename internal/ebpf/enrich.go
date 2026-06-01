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
	if f.Source.Container == "" {
		if cg, err := os.ReadFile(filepath.Join(p.ProcRoot, pid, "cgroup")); err == nil {
			f.Source.Container = containerIDFromCgroup(string(cg))
		}
	}
	if f.Source.Workload == "" {
		f.Source.Workload = resolveWorkload(f.Source)
	}
}

// resolveWorkload picks the best available identity for an endpoint: a short
// container id (qualified by process when known), else the process name, else
// empty (ID() then falls back to the address).
func resolveWorkload(e Endpoint) string {
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
