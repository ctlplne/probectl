// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build linux

package ebpf

import (
	"strings"
	"testing"
)

func TestKernelAtLeast(t *testing.T) {
	cases := []struct {
		rel      string
		maj, min int
		want     bool
	}{
		{"6.8.0-106-generic", 5, 8, true},
		{"5.8.0", 5, 8, true},
		{"5.7.19", 5, 8, false},
		{"4.19.0-26-amd64", 5, 8, false},
		{"6.1.0", 5, 8, true},
		{"garbage", 5, 8, false},
	}
	for _, c := range cases {
		if got := kernelAtLeast(c.rel, c.maj, c.min); got != c.want {
			t.Errorf("kernelAtLeast(%q,%d,%d) = %v, want %v", c.rel, c.maj, c.min, got, c.want)
		}
	}
}

func TestDigitPrefix(t *testing.T) {
	for in, want := range map[string]string{"106-generic": "106", "8": "8", "x": "", "0rc1": "0"} {
		if got := digitPrefix(in); got != want {
			t.Errorf("digitPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// EBPF-005: the probe distinguishes the LOAD capability (CAP_BPF) from the
// ATTACH capability (CAP_PERFMON) — and CAP_SYS_ADMIN implies both. Reasons
// name the missing capability so the agent fails fast and actionably,
// instead of loading objects and dying at attach.
func TestCapMaskPerfmonAndBPF(t *testing.T) {
	none := capMask(0)
	if none.has(capBPF) || none.has(capPerfmon) || none.has(capSysAdmin) {
		t.Fatal("empty mask must hold nothing")
	}
	bpfOnly := capMask(1 << capBPF)
	if !bpfOnly.has(capBPF) || bpfOnly.has(capPerfmon) {
		t.Fatal("CAP_BPF alone must not imply CAP_PERFMON — that is exactly the EBPF-005 bug")
	}
	pair := capMask(1<<capBPF | 1<<capPerfmon)
	if !pair.has(capBPF) || !pair.has(capPerfmon) {
		t.Fatal("the documented minimal pair must satisfy both checks")
	}
	admin := capMask(1 << capSysAdmin)
	if (!admin.has(capBPF) && !admin.has(capSysAdmin)) || (!admin.has(capPerfmon) && !admin.has(capSysAdmin)) {
		t.Fatal("CAP_SYS_ADMIN must satisfy both (the legacy catch-all)")
	}
}

// The live probe on this host must report BOTH capability dimensions and,
// when either is missing, an actionable reason naming the gap.
func TestProbeCapabilityReasons(t *testing.T) {
	c := Probe()
	if c.Mode == ModeUnavailable && c.Reason == "" {
		t.Fatal("unavailable must carry a reason")
	}
	if !c.CapBPF && c.Mode == ModeLive {
		t.Fatal("live mode without CAP_BPF is impossible")
	}
	if c.Compiled && c.BTF && c.RingBuffer && c.CapBPF && !c.CapPerfmon && c.Mode == ModeLive {
		t.Fatal("EBPF-005: ready-without-CAP_PERFMON must NOT report live")
	}
}

// DPR-054: a container that cannot see the node's tracefs must be told what to
// mount before anything loads, instead of dying at attach with "neither
// debugfs nor tracefs are mounted".
func TestDecideRequiresTraceFS(t *testing.T) {
	ready := Capabilities{Compiled: true, BTF: true, RingBuffer: true, CapBPF: true, CapPerfmon: true, TraceFS: true, KernelVersion: "6.6.0"}
	ready.decide()
	if ready.Mode != ModeLive || ready.Reason != "ready" {
		t.Fatalf("all preconditions met: mode=%s reason=%q", ready.Mode, ready.Reason)
	}
	noTraceFS := ready
	noTraceFS.TraceFS = false
	noTraceFS.decide()
	if noTraceFS.Mode != ModeUnavailable || !strings.Contains(noTraceFS.Reason, "/sys/kernel/tracing") || !strings.Contains(noTraceFS.Reason, "tracefs.hostPath") {
		t.Fatalf("missing tracefs must name the mount and the chart value: mode=%s reason=%q", noTraceFS.Mode, noTraceFS.Reason)
	}
	// The probe on this host reports the same dimension it decides on.
	if c := Probe(); c.TraceFS != traceFSVisible() {
		t.Fatalf("probe tracefs=%t, visible=%t", c.TraceFS, traceFSVisible())
	}
}
