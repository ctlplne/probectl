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
	CapBPF        bool // process holds CAP_BPF or CAP_SYS_ADMIN
	Compiled      bool // built with -tags ebpf (the live source is linked in)
}

// String renders a one-line summary for logs.
func (c Capabilities) String() string {
	return fmt.Sprintf("mode=%s os=%s arch=%s kernel=%q btf=%t ringbuf=%t cap_bpf=%t compiled=%t reason=%q",
		c.Mode, c.OS, c.Arch, c.KernelVersion, c.BTF, c.RingBuffer, c.CapBPF, c.Compiled, c.Reason)
}
