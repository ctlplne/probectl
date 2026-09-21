// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build linux

package ebpf

import (
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/ctlplne/probectl/internal/crypto"
)

// Attaching a uprobe through tracefs, without cilium/ebpf's Executable.
//
// Deliberately NOT behind the `ebpf` build tag: none of this needs a compiled
// BPF object, so it compiles and is checked on every build of this package
// rather than only where clang and a BPF toolchain exist.
//
// Why it exists (D-03, from DPR-125/126):
//
//   - link.OpenExecutable refuses a target with no execute bit. Debian and
//     Ubuntu package shared libraries 0644, so on the distributions most
//     operators run, the TLS capture could not attach to libssl at all. The
//     kernel has no such rule — trace_uprobe.c requires a regular file and
//     nothing more — so the check is library policy we can decline.
//   - cilium/ebpf tries the perf uprobe PMU and falls back to tracefs only when
//     the PMU is MISSING, never when creating it is refused. DPR-126 measured
//     the PMU refusing CAP_BPF+CAP_PERFMON and accepting CAP_SYS_ADMIN, which
//     lands in that second case, so the fallback never ran.
//
// This path therefore answers both, and — because the two mechanisms have
// different privilege requirements — lets the agent report which one actually
// worked instead of guessing.

// tracefsMounts are the two places the kernel exposes tracefs, newest first.
var tracefsMounts = []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}

// findTracefs returns the mounted tracefs directory that has uprobe_events.
func findTracefs() (string, error) {
	var tried []string
	for _, dir := range tracefsMounts {
		p := filepath.Join(dir, "uprobe_events")
		if _, err := os.Stat(p); err == nil {
			return dir, nil
		}
		tried = append(tried, p)
	}
	return "", fmt.Errorf("tracefs is not mounted (looked for %s). In a container it must be mounted from the host", strings.Join(tried, ", "))
}

// uprobeEventLine builds the command the kernel parses out of uprobe_events.
//
// The format is unforgiving and the failure mode is bad: a malformed line is
// rejected with a bare EINVAL from a write(2), which says nothing about which
// part was wrong. Building it in one place, with the rules written down, means
// the refusal happens here with a sentence instead of there with an errno.
//
//	p:<group>/<name> <path>:0x<offset>     entry probe
//	r:<group>/<name> <path>:0x<offset>     return probe
func uprobeEventLine(ret bool, group, name, libPath string, offset uint64) (string, error) {
	kind := "p"
	if ret {
		kind = "r"
	}
	if group == "" || name == "" {
		return "", errors.New("event group and name are required")
	}
	// The kernel splits the line on a space and the target on the LAST colon,
	// so neither can appear in the path. Escaping is not available, so a path
	// that cannot be expressed is refused rather than mangled.
	if libPath == "" {
		return "", errors.New("library path is required")
	}
	if !filepath.IsAbs(libPath) {
		return "", fmt.Errorf("library path %q must be absolute: the kernel resolves it in its own root, not the caller's working directory", libPath)
	}
	if strings.ContainsAny(libPath, " :\n") {
		return "", fmt.Errorf("library path %q contains a space, a colon or a newline, which the tracefs event format cannot express", libPath)
	}
	if strings.ContainsAny(group+name, " :/\n") {
		return "", fmt.Errorf("event name %q/%q may not contain a space, colon, slash or newline", group, name)
	}
	return fmt.Sprintf("%s:%s/%s %s:0x%x\n", kind, group, name, libPath, offset), nil
}

// readTraceEventID reads the tracepoint id the kernel assigned to the event.
func readTraceEventID(dir, group, name string) (int, error) {
	p := filepath.Join(dir, "events", group, name, "id")
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, fmt.Errorf("read event id %s: %w", p, err)
	}
	id, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, fmt.Errorf("parse event id from %s: %w", p, err)
	}
	return id, nil
}

// appendToFile opens with O_APPEND|O_WRONLY, which is how the kernel expects
// uprobe_events to be written: one command per write.
func appendToFile(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

// sanitizeEventName keeps a tracefs event name to what the kernel accepts:
// letters, digits and underscore.
func sanitizeEventName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		return "probe"
	}
	// The kernel caps the name; leave room for the random suffix.
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

// uprobeAttachment is an attached probe. Closing it detaches the BPF program
// and removes the tracefs event; leaving events behind would accumulate across
// agent restarts until the kernel's limit is hit.
type uprobeAttachment struct {
	perfFD     int
	eventsPath string
	group      string
	name       string
}

func (a *uprobeAttachment) Close() error {
	var errs []error
	if a.perfFD >= 0 {
		if err := unix.Close(a.perfFD); err != nil {
			errs = append(errs, fmt.Errorf("close perf event: %w", err))
		}
		a.perfFD = -1
	}
	if a.eventsPath != "" {
		if err := appendToFile(a.eventsPath, fmt.Sprintf("-:%s/%s\n", a.group, a.name)); err != nil {
			errs = append(errs, fmt.Errorf("remove tracefs event %s/%s: %w", a.group, a.name, err))
		}
		a.eventsPath = ""
	}
	return errors.Join(errs...)
}

// openUprobePerfEvent does everything up to attaching a BPF program: resolve
// the symbol, register the probe in tracefs, open the perf event.
//
// It is separate so the PRIVILEGE question can be measured without a compiled
// BPF object. D-01 turns on whether this path works under the agent's
// documented CAP_BPF+CAP_PERFMON, where the perf uprobe PMU demanded
// CAP_SYS_ADMIN (DPR-126); every step that could refuse is in here.
func openUprobePerfEvent(libPath, symbol string, ret bool) (*uprobeAttachment, error) {
	f, err := elf.Open(libPath)
	if err != nil {
		return nil, fmt.Errorf("uprobe: open %q: %w", libPath, err)
	}
	defer f.Close()
	offset, err := symbolFileOffset(f, symbol)
	if err != nil {
		return nil, fmt.Errorf("uprobe: %q in %q: %w", symbol, libPath, err)
	}

	dir, err := findTracefs()
	if err != nil {
		return nil, fmt.Errorf("uprobe: %w", err)
	}
	eventsPath := filepath.Join(dir, "uprobe_events")

	// A fresh name per attach: two agents, or one agent across a restart that
	// did not clean up, must not collide on a kernel-global event name.
	// Through internal/crypto, the repo's only crypto door (§7.3). Uniqueness
	// is what this needs rather than unpredictability, but the guard is
	// absolute on purpose and there is no reason to argue with it here.
	suffix, err := crypto.Random(6)
	if err != nil {
		return nil, fmt.Errorf("uprobe: name: %w", err)
	}
	group := "probectl"
	name := fmt.Sprintf("%s_%s", sanitizeEventName(symbol), hex.EncodeToString(suffix))

	line, err := uprobeEventLine(ret, group, name, libPath, offset)
	if err != nil {
		return nil, fmt.Errorf("uprobe: %w", err)
	}
	if err := appendToFile(eventsPath, line); err != nil {
		return nil, fmt.Errorf("uprobe: register %s at %s+0x%x: %w", symbol, libPath, offset, err)
	}
	att := &uprobeAttachment{perfFD: -1, eventsPath: eventsPath, group: group, name: name}

	id, err := readTraceEventID(dir, group, name)
	if err != nil {
		_ = att.Close()
		return nil, fmt.Errorf("uprobe: %w", err)
	}

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Config:      uint64(id),
		Size:        uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
	}
	// pid -1 with cpu 0 is the system-wide form: the perf event is the
	// attachment's lifetime handle, and the BPF program runs for hits on every
	// CPU regardless of which one this event names.
	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		_ = att.Close()
		return nil, fmt.Errorf("uprobe: open perf event for %s/%s: %w", group, name, err)
	}
	att.perfFD = fd
	return att, nil
}
