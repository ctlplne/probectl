package ebpf

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// libssl discovery (U-015): the TLS-uprobe L7 source used to hard-code the
// Debian/Ubuntu x86_64 multiarch path, so capture silently no-opped on every
// other arch/distro. Discovery now goes, in order: the PROBECTL_EBPF_LIBSSL
// override (handled by the caller) → the ldconfig shared-library cache (the
// dynamic linker's own truth) → well-known per-arch/per-distro candidates.
// A failure returns an error listing everything tried; the agent runtime
// logs it as a WARN and counts it (never a silent gap).

// archAlias maps GOARCH to the CPU component of the Debian/Ubuntu multiarch
// triplet directory ("<alias>-linux-gnu").
var archAlias = map[string]string{
	"amd64": "x86_64",
	"arm64": "aarch64",
}

// libsslNames are the SONAMEs to look for, newest first (OpenSSL 3, then 1.1).
var libsslNames = []string{"libssl.so.3", "libssl.so.1.1"}

// libsslCandidates returns the well-known install locations for goarch,
// newest library first: Debian/Ubuntu multiarch, RHEL/Fedora lib64,
// Alpine/Arch /usr/lib, and legacy /lib variants.
func libsslCandidates(goarch string) []string {
	var dirs []string
	if alias, ok := archAlias[goarch]; ok {
		dirs = append(dirs,
			"/usr/lib/"+alias+"-linux-gnu",
			"/lib/"+alias+"-linux-gnu",
		)
	}
	dirs = append(dirs, "/usr/lib64", "/usr/lib", "/lib64", "/lib")

	var out []string
	for _, name := range libsslNames {
		for _, d := range dirs {
			out = append(out, d+"/"+name)
		}
	}
	return out
}

// parseLdconfig extracts libssl paths from `ldconfig -p` output, whose lines
// look like:
//
//	libssl.so.3 (libc6,AArch64) => /usr/lib/aarch64-linux-gnu/libssl.so.3
//
// Paths are returned in libsslNames preference order (so.3 before so.1.1).
func parseLdconfig(out []byte) []string {
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
		for _, want := range libsslNames {
			if name == want && path != "" {
				byName[want] = append(byName[want], path)
			}
		}
	}
	var ordered []string
	for _, want := range libsslNames {
		ordered = append(ordered, byName[want]...)
	}
	return ordered
}

// discoverLibssl resolves the libssl shared object to attach uprobes to.
// ldconfig and exists are injectable for tests; see discoverLibsslDefault.
func discoverLibssl(goarch string, ldconfig func() ([]byte, error), exists func(string) bool) (string, error) {
	var tried []string
	if ldconfig != nil {
		if out, err := ldconfig(); err == nil {
			for _, p := range parseLdconfig(out) {
				if exists(p) {
					return p, nil
				}
				tried = append(tried, p)
			}
		}
	}
	for _, p := range libsslCandidates(goarch) {
		if exists(p) {
			return p, nil
		}
		tried = append(tried, p)
	}
	return "", fmt.Errorf("libssl not found for %s (tried ldconfig cache + %s); "+
		"set PROBECTL_EBPF_LIBSSL to the libssl path", goarch, strings.Join(tried, ", "))
}

// discoverLibsslDefault is the production discovery: the host's ldconfig
// cache first, then the per-arch candidates for the running GOARCH.
func discoverLibsslDefault() (string, error) {
	return discoverLibssl(runtime.GOARCH,
		func() ([]byte, error) { return exec.Command("ldconfig", "-p").Output() },
		func(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() },
	)
}
