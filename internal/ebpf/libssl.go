// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// TLS library discovery (U-015/EBPF-001): the TLS-uprobe L7 source used to
// hard-code one Debian/Ubuntu x86_64 libssl path, so capture silently no-opped
// on every other arch/distro. Discovery now goes, in order: the optional
// PROBECTL_EBPF_LIBSSL override for OpenSSL-compatible stacks (handled by the
// caller) -> the ldconfig shared-library cache (the dynamic linker's own truth)
// -> well-known per-arch/per-distro candidates. A failure returns an error
// listing everything tried; the agent runtime logs it as a WARN and counts it
// (never a silent gap).

// archAlias maps GOARCH to the CPU component of the Debian/Ubuntu multiarch
// triplet directory ("<alias>-linux-gnu").
var archAlias = map[string]string{
	"amd64": "x86_64",
	"arm64": "aarch64",
}

// libsslNames are the SONAMEs to look for, newest first (OpenSSL 3, then 1.1).
var libsslNames = []string{"libssl.so.3", "libssl.so.1.1"}

// libgnutlsNames are the GnuTLS SONAMEs to look for, newest mainstream ABI
// first. libgnutls.so.30 covers current distro releases; .28 covers older
// supported fleet images.
var libgnutlsNames = []string{"libgnutls.so.30", "libgnutls.so.28"}

type tlsProbeLibrary struct {
	name        string
	path        string
	writeSymbol string
	readSymbol  string
}

func sharedLibraryCandidates(goarch string, names []string) []string {
	var dirs []string
	if alias, ok := archAlias[goarch]; ok {
		dirs = append(dirs,
			"/usr/lib/"+alias+"-linux-gnu",
			"/lib/"+alias+"-linux-gnu",
		)
	}
	dirs = append(dirs, "/usr/lib64", "/usr/lib", "/lib64", "/lib")

	var out []string
	for _, name := range names {
		for _, d := range dirs {
			out = append(out, d+"/"+name)
		}
	}
	return out
}

// libsslCandidates returns the well-known install locations for goarch,
// newest library first: Debian/Ubuntu multiarch, RHEL/Fedora lib64,
// Alpine/Arch /usr/lib, and legacy /lib variants.
func libsslCandidates(goarch string) []string {
	return sharedLibraryCandidates(goarch, libsslNames)
}

// libgnutlsCandidates returns the well-known install locations for goarch,
// newest library first: Debian/Ubuntu multiarch, RHEL/Fedora lib64,
// Alpine/Arch /usr/lib, and legacy /lib variants.
func libgnutlsCandidates(goarch string) []string {
	return sharedLibraryCandidates(goarch, libgnutlsNames)
}

// parseLdconfig extracts libssl paths from `ldconfig -p` output, whose lines
// look like:
//
//	libssl.so.3 (libc6,AArch64) => /usr/lib/aarch64-linux-gnu/libssl.so.3
//
// Paths are returned in libsslNames preference order (so.3 before so.1.1).
func parseLdconfig(out []byte) []string {
	return parseLdconfigForNames(out, libsslNames)
}

func parseLdconfigForNames(out []byte, names []string) []string {
	byName := map[string][]string{}
	for _, line := range strings.Split(string(out), "\n") {
		name, path, ok := strings.Cut(line, "=>")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if i := strings.IndexByte(name, ' '); i > 0 {
			name = name[:i]
		}
		path = strings.TrimSpace(path)
		for _, want := range names {
			if name == want && path != "" {
				byName[want] = append(byName[want], path)
			}
		}
	}
	var ordered []string
	for _, want := range names {
		ordered = append(ordered, byName[want]...)
	}
	return ordered
}

func discoverSharedLibrary(goarch string, names []string, candidates []string, label string, hint string, ldconfig func() ([]byte, error), exists func(string) bool) (string, error) {
	var tried []string
	if ldconfig != nil {
		if out, err := ldconfig(); err == nil {
			for _, p := range parseLdconfigForNames(out, names) {
				if exists(p) {
					return p, nil
				}
				tried = append(tried, p)
			}
		}
	}
	for _, p := range candidates {
		if exists(p) {
			return p, nil
		}
		tried = append(tried, p)
	}
	msg := fmt.Sprintf("%s not found for %s (tried ldconfig cache + %s)", label, goarch, strings.Join(tried, ", "))
	if hint != "" {
		msg += "; " + hint
	}
	return "", fmt.Errorf("%s", msg)
}

// discoverLibssl resolves the OpenSSL-compatible libssl shared object to
// attach uprobes to. ldconfig and exists are injectable for tests; see
// discoverLibsslDefault.
func discoverLibssl(goarch string, ldconfig func() ([]byte, error), exists func(string) bool) (string, error) {
	return discoverSharedLibrary(goarch, libsslNames, libsslCandidates(goarch), "libssl",
		"set PROBECTL_EBPF_LIBSSL to the libssl path", ldconfig, exists)
}

// discoverLibgnutls resolves the GnuTLS shared object to attach uprobes to.
// It has no override knob: PROBECTL_EBPF_LIBSSL remains specific to OpenSSL-
// compatible libraries, while GnuTLS is auto-discovered when present.
func discoverLibgnutls(goarch string, ldconfig func() ([]byte, error), exists func(string) bool) (string, error) {
	return discoverSharedLibrary(goarch, libgnutlsNames, libgnutlsCandidates(goarch), "libgnutls", "", ldconfig, exists)
}

// discoverLibsslDefault is the production discovery: the host's ldconfig
// cache first, then the per-arch candidates for the running GOARCH.
func discoverLibsslDefault() (string, error) {
	return discoverLibssl(runtime.GOARCH,
		func() ([]byte, error) { return exec.Command("ldconfig", "-p").Output() },
		func(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() },
	)
}

// discoverLibgnutlsDefault is the production GnuTLS discovery: the host's
// ldconfig cache first, then the per-arch candidates for the running GOARCH.
func discoverLibgnutlsDefault() (string, error) {
	return discoverLibgnutls(runtime.GOARCH,
		func() ([]byte, error) { return exec.Command("ldconfig", "-p").Output() },
		func(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() },
	)
}

func discoverTLSProbeLibraries(goarch string, libsslOverride string, ldconfig func() ([]byte, error), exists func(string) bool) ([]tlsProbeLibrary, error) {
	var libs []tlsProbeLibrary
	var failures []error
	if libsslOverride != "" {
		libs = append(libs, tlsProbeLibrary{
			name:        "openssl",
			path:        libsslOverride,
			writeSymbol: "SSL_write",
			readSymbol:  "SSL_read",
		})
	} else if p, err := discoverLibssl(goarch, ldconfig, exists); err == nil {
		libs = append(libs, tlsProbeLibrary{
			name:        "openssl",
			path:        p,
			writeSymbol: "SSL_write",
			readSymbol:  "SSL_read",
		})
	} else {
		failures = append(failures, err)
	}

	if p, err := discoverLibgnutls(goarch, ldconfig, exists); err == nil {
		libs = append(libs, tlsProbeLibrary{
			name:        "gnutls",
			path:        p,
			writeSymbol: "gnutls_record_send",
			readSymbol:  "gnutls_record_recv",
		})
	} else {
		failures = append(failures, err)
	}

	if len(libs) > 0 {
		return libs, nil
	}

	var parts []string
	for _, err := range failures {
		parts = append(parts, err.Error())
	}
	return nil, fmt.Errorf("no supported TLS uprobe libraries found for %s (%s)", goarch, strings.Join(parts, "; "))
}

func discoverTLSProbeLibrariesDefault(libsslOverride string) ([]tlsProbeLibrary, error) {
	return discoverTLSProbeLibraries(runtime.GOARCH, libsslOverride,
		func() ([]byte, error) { return exec.Command("ldconfig", "-p").Output() },
		func(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() },
	)
}
