// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build linux

package ebpf

import (
	"os"
	"strings"
	"testing"
)

// The live half of D-01/D-03: does a uprobe attach to a shared library that a
// distribution packaged 0644, and what privilege does the attach actually need?
//
// Off by default and never in CI: it writes to the kernel's global
// uprobe_events, so it needs a real machine and an explicit opt-in.
//
//	PROBECTL_UPROBE_LIVE=/usr/lib/aarch64-linux-gnu/libssl.so.3 go test ./internal/ebpf/ -run Live -v
//
// Run it under different capability sets to get the answer D-01 turns on:
//
//	docker run --cap-drop=ALL --cap-add=BPF --cap-add=PERFMON …   (documented agent privilege)
//	docker run --cap-drop=ALL --cap-add=SYS_ADMIN …               (what DPR-126 measured the PMU needing)
func TestLiveUprobeAttachesToAPackagedLibrary(t *testing.T) {
	lib := os.Getenv("PROBECTL_UPROBE_LIVE")
	if lib == "" {
		t.Skip("set PROBECTL_UPROBE_LIVE=/path/to/libssl.so.3 to measure a real attach")
	}
	info, err := os.Stat(lib)
	if err != nil {
		t.Fatalf("stat %s: %v", lib, err)
	}
	// The whole point: report the mode, so the result is read against what the
	// distribution actually shipped rather than against an assumption.
	t.Logf("target %s mode %v (execute bit: %v)", lib, info.Mode().Perm(), info.Mode().Perm()&0o111 != 0)

	for _, sym := range []string{"SSL_write", "SSL_read"} {
		for _, ret := range []bool{false, true} {
			kind := "entry"
			if ret {
				kind = "return"
			}
			att, err := openUprobePerfEvent(lib, sym, ret)
			if err != nil {
				t.Errorf("%s %s probe: %v", sym, kind, err)
				continue
			}
			t.Logf("%s %s probe: attached (tracefs event %s/%s, perf fd %d)", sym, kind, att.group, att.name, att.perfFD)
			if err := att.Close(); err != nil {
				t.Errorf("%s %s probe: detach: %v", sym, kind, err)
			}
		}
	}
}

// A second, cheaper signal for the same question: whether this process can even
// write the tracefs event, which is the step that does not need perf at all.
func TestLiveTracefsIsWritable(t *testing.T) {
	if os.Getenv("PROBECTL_UPROBE_LIVE") == "" {
		t.Skip("set PROBECTL_UPROBE_LIVE to run the live probes")
	}
	dir, err := findTracefs()
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("tracefs at %s", dir)
	f, err := os.OpenFile(dir+"/uprobe_events", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("uprobe_events is not writable by this process: %v", err)
	}
	_ = f.Close()
	t.Log("uprobe_events is writable")
	if strings.Contains(dir, "debug") {
		t.Log("note: this is the debugfs mount; the newer /sys/kernel/tracing needs no debugfs")
	}
}
