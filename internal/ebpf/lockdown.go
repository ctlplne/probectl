// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import "strings"

// parseLockdown reads the active mode from the kernel's
// /sys/kernel/security/lockdown content (e.g. "none [integrity] confidentiality"
// → "integrity"). Returns "" when no mode is bracketed/unreadable (U-075).
func parseLockdown(content string) string {
	for _, tok := range strings.Fields(content) {
		if strings.HasPrefix(tok, "[") && strings.HasSuffix(tok, "]") {
			return strings.Trim(tok, "[]")
		}
	}
	return ""
}

// lockdownBlocksBPF reports whether the lockdown mode prevents loading eBPF.
// Confidentiality lockdown blocks bpf() even with CAP_BPF/root; integrity mode
// permits signed/normal BPF loading.
func lockdownBlocksBPF(mode string) bool { return mode == "confidentiality" }

// maxRingBufferBytes caps the configurable ring buffer (EBPF-005). The ring
// buffer is unswappable kernel memory pinned per agent; 256 MiB is already far
// beyond any sane flow-buffering need. config.validate() rejects anything
// larger before Load() rounds it up to the next power of two.
const maxRingBufferBytes = 256 << 20 // 256 MiB

// ringBufferBytes rounds a requested ring-buffer size to a value the kernel
// accepts for BPF_MAP_TYPE_RINGBUF: a power of two that is at least one page
// (4 KiB). 0/negative requests fall back to the 16 MiB default (U-050).
func ringBufferBytes(req int) uint32 {
	const page = 4096
	const def = 1 << 24 // 16 MiB
	if req <= 0 {
		return def
	}
	if req < page {
		req = page
	}
	// Round UP to the next power of two.
	n := uint32(page)
	for n < uint32(req) && n < (1<<31) {
		n <<= 1
	}
	return n
}
