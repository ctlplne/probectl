// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import "testing"

func TestParseLockdown(t *testing.T) {
	cases := map[string]string{
		"none [integrity] confidentiality\n": "integrity",
		"none integrity [confidentiality]":   "confidentiality",
		"[none] integrity confidentiality":   "none",
		"none integrity confidentiality":     "", // nothing active/bracketed
		"":                                   "",
		"[confidentiality]":                  "confidentiality",
	}
	for in, want := range cases {
		if got := parseLockdown(in); got != want {
			t.Errorf("parseLockdown(%q) = %q, want %q", in, got, want)
		}
	}
	if !lockdownBlocksBPF("confidentiality") {
		t.Error("confidentiality must block bpf")
	}
	if lockdownBlocksBPF("integrity") || lockdownBlocksBPF("none") || lockdownBlocksBPF("") {
		t.Error("only confidentiality blocks bpf")
	}
}

func TestRingBufferBytes(t *testing.T) {
	cases := []struct {
		req  int
		want uint32
	}{
		{0, 1 << 24},       // default
		{-5, 1 << 24},      // invalid → default
		{1, 4096},          // below a page → one page
		{4096, 4096},       // exact page
		{5000, 8192},       // round up to next power of two
		{1 << 20, 1 << 20}, // already a power of two
		{(1 << 20) + 1, 1 << 21},
		{maxRingBufferBytes, maxRingBufferBytes}, // EBPF-005: 256 MiB is a valid power-of-two ceiling
	}
	for _, c := range cases {
		if got := ringBufferBytes(c.req); got != c.want {
			t.Errorf("ringBufferBytes(%d) = %d, want %d", c.req, got, c.want)
		}
		// Always a power of two and at least one page.
		if got := ringBufferBytes(c.req); got&(got-1) != 0 || got < 4096 {
			t.Errorf("ringBufferBytes(%d) = %d is not a valid ringbuf size", c.req, got)
		}
	}
}
