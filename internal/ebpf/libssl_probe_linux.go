// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build linux

package ebpf

import "os"

// The filesystem predicates discovery uses to decide whether a candidate TLS
// library is worth trying.
//
// Deliberately NOT behind the `ebpf` build tag. hostLibraryAttachable once
// required an execute bit, which silently turned the whole L7 capability off on
// Debian and Ubuntu — and it could not be unit-tested, because everything in
// its file needed a compiled BPF object and a clang toolchain. A predicate that
// can disable a capability on its own belongs where a test can reach it.

func hostLibraryExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// hostLibraryAttachable reports whether a present library is in a form some
// attach path accepts.
//
// It used to require an execute bit, because cilium/ebpf's OpenExecutable does
// and Debian/Ubuntu package shared libraries 0644 (DPR-125). That filter is now
// wrong in the other direction: the in-repo tracefs path attaches to a 0644
// library perfectly well — the kernel only requires a regular file — so
// refusing one here means discovery rejects a library the agent can actually
// probe, and the capability stays off for the distributions it was meant to fix.
// Found by retesting the shipped DaemonSet, which still refused after the
// attach path landed and its own tests passed.
//
// The execute bit is no longer a property of DISCOVERY. It decides which attach
// path is used, and attachTLSLibrary reports both attempts when neither works.
func hostLibraryAttachable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}
