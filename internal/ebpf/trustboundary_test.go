// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ebpf

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// EBPF-003 trust boundary (decided per the triage rule): probectl does NOT
// support operator-supplied BPF objects, so load-time signature verification
// has nothing to verify that the existing chain doesn't already cover:
//
//	source (bpf/*.bpf.c, reviewed)
//	  → bpf2go at build time (clang, pinned toolchain)
//	  → EMBEDDED into the agent binary (go:embed; no filesystem load path)
//	  → SHA-256 manifest baked at the same build (gendigests, U-014)
//	  → VerifyObjectDigest before the kernel ever sees the bytes
//	  → the agent BINARY (and image) is cosign-signed at release (C6/U-067)
//
// The binary signature covers the embedded objects and the manifest
// TOGETHER, so a swapped object can't ride a signed binary, and a patched
// manifest invalidates the binary signature. Introducing an operator-
// supplied object path would ADD attack surface and would require its own
// signature scheme — deliberately not supported.
//
// This static gate keeps the boundary honest: no code under internal/ebpf
// may load BPF object bytes from the filesystem or environment. If a
// legitimate need ever arises, this test is the tripwire forcing the
// signature design EBPF-003 anticipated.
func TestNoOperatorSuppliedBPFObjectPath(t *testing.T) {
	// Loading BPF bytes happens via these cilium/ebpf entry points; the only
	// blessed callers are the bpf2go-generated load*Objects functions, which
	// read the EMBEDDED byte slices.
	loadRe := regexp.MustCompile(`ebpf\.LoadCollectionSpec\(|ebpf\.LoadCollectionSpecFromReader\(|NewCollectionWithOptions\(|os\.ReadFile\([^)]*\.o"`)

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || strings.HasPrefix(filepath.Base(f), "sslsniff_") || strings.HasPrefix(filepath.Base(f), "l4flow_") {
			continue // tests and bpf2go-generated loaders (embedded bytes only)
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := loadRe.Find(src); m != nil {
			t.Errorf("%s: %q — BPF objects must be EMBEDDED (bpf2go) and digest-verified, never loaded from disk/env (EBPF-003 trust boundary)", f, m)
		}
		// No config/env key may smuggle an object path either.
		if strings.Contains(string(src), "OBJECT_PATH") || strings.Contains(string(src), "object_path") {
			t.Errorf("%s: an object-path config key violates the embedded-object trust boundary (EBPF-003)", f)
		}
	}
}

// The other half of EBPF-003's chain: every live loader must verify its
// embedded object against the manifest BEFORE the kernel load (fail-closed
// behavior is covered by TestVerifyObjectDigest*), and the manifest
// generator must cover every bpf2go output (it globs *_bpfel.o — both
// sslsniff arches and l4flow land there).
func TestObjectDigestVerificationWiredIntoEveryLoader(t *testing.T) {
	for _, f := range []string{"source_live_linux.go", "source_live_l7_linux.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("live loader %s missing: %v", f, err)
		}
		text := string(src)
		vi := strings.Index(text, "VerifyObjectDigest(")
		li := strings.Index(text, "Objects(")
		if vi < 0 {
			t.Errorf("%s: loader does not call VerifyObjectDigest — integrity must gate every kernel load (U-014/EBPF-003)", f)
			continue
		}
		if li >= 0 && li < vi {
			t.Errorf("%s: objects are loaded BEFORE digest verification — verify must come first", f)
		}
	}
	gen, err := os.ReadFile("gendigests/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gen), `*_bpfel.o`) {
		t.Error("gendigests must glob every bpf2go object (*_bpfel.o) so the manifest covers all embedded programs")
	}
}
