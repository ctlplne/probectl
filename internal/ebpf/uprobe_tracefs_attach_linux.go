// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build linux && ebpf

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// The half of the tracefs uprobe path that needs a loaded BPF program.
//
// Split out of uprobe_tracefs_linux.go because its ONLY consumer —
// source_live_l7_linux.go — is `linux && ebpf` while that file is plain
// `linux`. The mismatch was not cosmetic: in a plain-linux build these symbols
// compiled with nothing able to reach them, and golangci-lint on a Linux host
// correctly reported attachUprobeViaTracefs and the two mechanism constants as
// unused. It was invisible on a macOS developer machine, where every _linux.go
// file is excluded from the build and therefore from the linter too, so the
// whole class of Linux-only lint findings cannot be seen there at all.
//
// The pure helpers it calls — findTracefs, uprobeEventLine, readTraceEventID,
// sanitizeEventName — deliberately stay at plain `linux` with their tests, so
// they keep being exercised by the ordinary test-go job rather than only inside
// the kernel matrix.

// The two ways a uprobe can end up attached, reported so an operator can see
// which one a node needed rather than inferring it.
const (
	attachViaLibrary = "cilium-ebpf"
	attachViaTracefs = "tracefs"
)

// attachUprobeViaTracefs registers a uprobe on symbol in libPath and attaches
// prog to it. ret selects a return probe.
func attachUprobeViaTracefs(libPath, symbol string, prog *cebpf.Program, ret bool) (*uprobeAttachment, error) {
	if prog == nil {
		return nil, errors.New("uprobe: program is nil")
	}
	att, err := openUprobePerfEvent(libPath, symbol, ret)
	if err != nil {
		return nil, err
	}
	if err := unix.IoctlSetInt(att.perfFD, unix.PERF_EVENT_IOC_SET_BPF, prog.FD()); err != nil {
		_ = att.Close()
		return nil, fmt.Errorf("uprobe: attach program to %s/%s: %w", att.group, att.name, err)
	}
	if err := unix.IoctlSetInt(att.perfFD, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		_ = att.Close()
		return nil, fmt.Errorf("uprobe: enable %s/%s: %w", att.group, att.name, err)
	}
	return att, nil
}
