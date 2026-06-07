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
	c.CapBPF = hasBPFCapability()
	c.Lockdown = lockdownMode()

	switch {
	case !c.Compiled:
		c.Mode, c.Reason = ModeUnavailable, "eBPF live source not compiled in (build with -tags ebpf)"
	case !c.BTF:
		c.Mode, c.Reason = ModeUnavailable, "kernel BTF (/sys/kernel/btf/vmlinux) not found; CO-RE unavailable (try BTFHub)"
	case !c.RingBuffer:
		c.Mode, c.Reason = ModeUnavailable, fmt.Sprintf("kernel %q lacks the BPF ring buffer (need >= 5.8)", c.KernelVersion)
	case !c.CapBPF:
		c.Mode, c.Reason = ModeUnavailable, "process lacks CAP_BPF / CAP_SYS_ADMIN to load eBPF"
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

func hasBPFCapability() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if err != nil {
			return false
		}
		return mask&(1<<capSysAdmin) != 0 || mask&(1<<capBPF) != 0
	}
	return false
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
