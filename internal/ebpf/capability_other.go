//go:build !linux

package ebpf

import "runtime"

// Probe reports eBPF unavailable on non-Linux hosts: eBPF is Linux-only, so on
// macOS/Windows the agent runs inside a Linux VM (docs/ebpf-feasibility.md §3).
func Probe() Capabilities {
	return Capabilities{
		Mode:     ModeUnavailable,
		Reason:   "eBPF is Linux-only (run the agent inside a Linux VM on " + runtime.GOOS + ")",
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Compiled: liveCompiled,
	}
}
