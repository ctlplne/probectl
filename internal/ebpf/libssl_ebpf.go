// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build linux && ebpf

package ebpf

import (
	"os/exec"
	"runtime"
)

func hostLdconfig() ([]byte, error) {
	return exec.Command("ldconfig", "-p").Output()
}

func discoverTLSProbeLibrariesDefault(libsslOverride, hostRoot string) ([]tlsProbeLibrary, error) {
	return discoverTLSProbeLibraries(runtime.GOARCH, libsslOverride, hostRoot, hostLdconfig, hostLibraryExists, hostLibraryAttachable)
}
