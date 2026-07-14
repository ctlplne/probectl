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

func discoverTLSProbeLibrariesDefault(libsslOverride string) ([]tlsProbeLibrary, error) {
	return discoverTLSProbeLibraries(runtime.GOARCH, libsslOverride, hostLdconfig, hostLibraryExists)
}
