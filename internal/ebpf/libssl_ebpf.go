// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build linux && ebpf

package ebpf

import (
	"os"
	"os/exec"
	"runtime"
)

func hostLdconfig() ([]byte, error) {
	return exec.Command("ldconfig", "-p").Output()
}

func hostLibraryExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// hostLibraryAttachable reports whether a present library is in a form the
// uprobe loader accepts. cilium/ebpf link.OpenExecutable refuses any target
// without an execute bit, and Debian/Ubuntu package shared libraries 0644
// (DPR-125), so this is checked during discovery — a node that also carries an
// attachable copy should be found instead of failing at attach time.
func hostLibraryAttachable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Mode().Perm()&0o111 != 0
}

func discoverTLSProbeLibrariesDefault(libsslOverride, hostRoot string) ([]tlsProbeLibrary, error) {
	return discoverTLSProbeLibraries(runtime.GOARCH, libsslOverride, hostRoot, hostLdconfig, hostLibraryExists, hostLibraryAttachable)
}
