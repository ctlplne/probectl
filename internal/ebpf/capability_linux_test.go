// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build linux

package ebpf

import "testing"

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
