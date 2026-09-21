// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVendoredLibbpfHeaders guards the vendored libbpf BPF-program headers.
//
// The BPF objects are compiled (bpf2go → clang) against the libbpf headers
// VENDORED under bpf/headers — deliberately NOT against the build host's
// libbpf-dev. sslsniff.bpf.c uses BPF_UPROBE/BPF_URETPROBE, macros libbpf only
// added in v1.2.0; building against an older system libbpf (e.g. Debian
// bookworm's 1.1.0, shipped by the golang:1.26-bookworm agent image) failed
// the whole eBPF image build with "use of undeclared identifier 'BPF_UPROBE'".
//
// This test fails LOUDLY and cheaply — no clang, kernel, BTF, or -tags ebpf
// needed, so it runs in the ordinary unit-test job — if the vendored set is
// deleted, made incomplete, or regressed below the BPF_UPROBE floor. That keeps
// the breakage from silently reaching the slow, required ebpf-image-live job.
// See internal/ebpf/bpf/headers/VENDOR.md.
func TestVendoredLibbpfHeaders(t *testing.T) {
	dir := filepath.Join("bpf", "headers", "bpf")

	// The BPF-program header set the .bpf.c files compile against (closure of
	// what l4flow.bpf.c and sslsniff.bpf.c #include, transitively).
	for _, h := range []string{
		"bpf_helpers.h",
		"bpf_helper_defs.h",
		"bpf_tracing.h",
		"bpf_core_read.h",
		"bpf_endian.h",
	} {
		if _, err := os.Stat(filepath.Join(dir, h)); err != nil {
			t.Errorf("vendored libbpf header missing: %s (%v) — restore the set per %s",
				h, err, filepath.Join("bpf", "headers", "VENDOR.md"))
		}
	}

	// The exact macros whose absence broke the build. Their presence pins the
	// vendored libbpf at the >= v1.2.0 floor that defines them.
	tracing := filepath.Join(dir, "bpf_tracing.h")
	b, err := os.ReadFile(tracing)
	if err != nil {
		t.Fatalf("cannot read vendored bpf_tracing.h (%s): %v", tracing, err)
	}
	src := string(b)
	for _, macro := range []string{"BPF_UPROBE", "BPF_URETPROBE"} {
		if !strings.Contains(src, "#define "+macro) {
			t.Errorf("vendored bpf_tracing.h does not #define %s: the vendored libbpf "+
				"predates v1.2.0, but sslsniff.bpf.c requires it (see bpf/headers/VENDOR.md)", macro)
		}
	}
}
