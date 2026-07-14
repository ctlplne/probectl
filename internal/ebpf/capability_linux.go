// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build linux

package ebpf

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Linux capability numbers (see <linux/capability.h>).
const (
	capSysAdmin = 21
	capPerfmon  = 38
	capBPF      = 39
)

// Probe inspects the host for eBPF readiness. It is read-only, needs no
// privileges, and loads no programs — only the live source (-tags ebpf) ever
// calls the bpf() syscall.
func Probe() Capabilities {
	c := Capabilities{
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Compiled:      liveCompiled,
		KernelVersion: unameRelease(),
	}
	c.BTF = fileExists("/sys/kernel/btf/vmlinux")
	c.RingBuffer = kernelAtLeast(c.KernelVersion, 5, 8)
	caps := effectiveCaps()
	c.CapBPF = caps.has(capBPF) || caps.has(capSysAdmin)
	// EBPF-005: loading is only half the job — attaching the tracepoints and
	// uprobes goes through perf_event_open, which needs CAP_PERFMON (>= 5.8)
	// or CAP_SYS_ADMIN. Without this check the probe reported "ready" and
	// the agent failed later at attach. CAP_NET_ADMIN is NOT required: the
	// agent attaches no TC/XDP programs (observe-only guardrail).
	c.CapPerfmon = caps.has(capPerfmon) || caps.has(capSysAdmin)
	c.Lockdown = lockdownMode()

	switch {
	case !c.Compiled:
		c.Mode, c.Reason = ModeUnavailable, "eBPF live source not compiled in (build with -tags ebpf)"
	case !c.BTF:
		c.Mode, c.Reason = ModeUnavailable, "kernel BTF (/sys/kernel/btf/vmlinux) not found; CO-RE unavailable (try BTFHub)"
	case !c.RingBuffer:
		c.Mode, c.Reason = ModeUnavailable, fmt.Sprintf("kernel %q lacks the BPF ring buffer (need >= 5.8)", c.KernelVersion)
	case !c.CapBPF:
		c.Mode, c.Reason = ModeUnavailable, "process lacks CAP_BPF / CAP_SYS_ADMIN to LOAD eBPF programs (grant the CAP_BPF + CAP_PERFMON pair, e.g. AmbientCapabilities in the shipped unit)"
	case !c.CapPerfmon:
		c.Mode, c.Reason = ModeUnavailable, "process lacks CAP_PERFMON / CAP_SYS_ADMIN to ATTACH tracepoints/uprobes (perf_event_open) — programs would load and then fail at attach; grant CAP_PERFMON alongside CAP_BPF (EBPF-005)"
	case lockdownBlocksBPF(c.Lockdown):
		c.Mode, c.Reason = ModeUnavailable, "kernel lockdown is in CONFIDENTIALITY mode — bpf() is blocked even with CAP_BPF; boot without lockdown=confidentiality (or use integrity mode) to run the eBPF agent (U-075)"
	default:
		c.Mode, c.Reason = ModeLive, "ready"
	}
	return c
}

func unameRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return charsToString(u.Release)
}

func charsToString(b [65]byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

// kernelAtLeast reports whether a "MAJOR.MINOR[.PATCH-...]" release string is at
// least major.minor.
func kernelAtLeast(release string, major, minor int) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	maj, err1 := strconv.Atoi(digitPrefix(parts[0]))
	mnr, err2 := strconv.Atoi(digitPrefix(parts[1]))
	if err1 != nil || err2 != nil {
		return false
	}
	if maj != major {
		return maj > major
	}
	return mnr >= minor
}

func digitPrefix(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

// capMask is the process's effective capability set.
type capMask uint64

func (m capMask) has(bit uint) bool { return m&(1<<bit) != 0 }

// effectiveCaps parses CapEff from /proc/self/status (0 on any error — a
// process whose capabilities can't be read claims none).
func effectiveCaps() capMask {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if err != nil {
			return 0
		}
		return capMask(mask)
	}
	return 0
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
