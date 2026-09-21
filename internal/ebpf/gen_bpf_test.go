// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"os"
	"strings"
	"testing"
)

// TestGenBpfScript guards gen_bpf.sh, the single source of truth for the BPF
// object compile (bpf2go → clang). It must keep doing three things, because
// losing any of them silently reintroduces a CI break we already fixed — and
// it would only resurface in the slow image / arm64-matrix builds, not here:
//
//   - "-I./bpf/headers": compile against the VENDORED libbpf headers, not the
//     build host's libbpf-dev (bookworm's 1.1 lacks BPF_UPROBE; see
//     vendored_headers_test.go and bpf/headers/VENDOR.md).
//   - 'struct user_pt_regs {': probe the dumped vmlinux.h for the arm64
//     register struct...
//   - "-DPROBECTL_VMLINUX_HAS_USER_PT_REGS": ...and set arch_compat.h's opt-out
//     when it is already present, so native-arm64 builds don't redefine it.
//
// Cheap content check: no clang, kernel, BTF, or -tags ebpf needed, so a
// regression trips the ordinary unit job.
func TestGenBpfScript(t *testing.T) {
	b, err := os.ReadFile("gen_bpf.sh")
	if err != nil {
		t.Fatalf("cannot read gen_bpf.sh: %v", err)
	}
	s := string(b)
	for _, want := range []string{
		"-I./bpf/headers",
		"struct user_pt_regs {",
		"-DPROBECTL_VMLINUX_HAS_USER_PT_REGS",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("gen_bpf.sh no longer contains %q — a BPF-build guard was lost "+
				"(see internal/ebpf/source_live_l7_linux.go and bpf/arch_compat.h)", want)
		}
	}
}
