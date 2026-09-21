// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import "fmt"

// Mode is whether the eBPF live source can run on this host + build.
type Mode string

const (
	// ModeLive means eBPF programs can be loaded and run here.
	ModeLive Mode = "live"
	// ModeUnavailable means they cannot; Reason explains why.
	ModeUnavailable Mode = "unavailable"
)

// Capabilities is the result of probing the host for eBPF readiness. It is
// surfaced to operators (and, later, the control plane as a host-capability
// flag) so an unsupported host is a DECIDED, visible state — not a silent
// failure (S19a / docs/ebpf-feasibility.md §11).
type Capabilities struct {
	Mode          Mode
	Reason        string
	OS            string
	Arch          string
	KernelVersion string
	BTF           bool // /sys/kernel/btf/vmlinux present (CO-RE relocation)
	RingBuffer    bool // kernel >= 5.8 (BPF_MAP_TYPE_RINGBUF)
	CapBPF        bool // process holds CAP_BPF or CAP_SYS_ADMIN (program/map load)
	// CapPerfmon: CAP_PERFMON or CAP_SYS_ADMIN — required to ATTACH the
	// tracepoints and uprobes (perf_event_open) on kernels >= 5.8. Probed
	// here so the agent fails fast with a clear reason instead of loading
	// objects and then failing at attach (EBPF-005). CAP_NET_ADMIN is
	// deliberately NOT probed: the agent attaches only tracepoints + uprobes
	// (observe-only) — no TC/XDP — so it never needs it (the systemd unit
	// documents the same pair).
	CapPerfmon bool
	// TraceFS: the kernel's tracefs is visible (/sys/kernel/tracing, or the
	// legacy /sys/kernel/debug/tracing). Attaching the sock:inet_sock_set_state
	// tracepoint reads the event id there, and a container does not see the
	// host's tracefs unless it is mounted in (DPR-054).
	TraceFS  bool
	Compiled bool // built with -tags ebpf (the live source is linked in)
	// Lockdown is the kernel lockdown mode ("", "none", "integrity",
	// "confidentiality"); confidentiality mode blocks bpf() even with
	// CAP_BPF (U-075).
	Lockdown string
}

// String renders a one-line summary for logs.
func (c Capabilities) String() string {
	return fmt.Sprintf("mode=%s os=%s arch=%s kernel=%q btf=%t ringbuf=%t cap_bpf=%t cap_perfmon=%t tracefs=%t lockdown=%q compiled=%t reason=%q",
		c.Mode, c.OS, c.Arch, c.KernelVersion, c.BTF, c.RingBuffer, c.CapBPF, c.CapPerfmon, c.TraceFS, c.Lockdown, c.Compiled, c.Reason)
}
