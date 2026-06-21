// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
