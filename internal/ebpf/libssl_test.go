// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"errors"
	"strings"
	"testing"
)

func existsSet(paths ...string) func(string) bool {
	set := map[string]bool{}
	for _, p := range paths {
		set[p] = true
	}
	return func(p string) bool { return set[p] }
}

// U-015 aarch64 smoke: on an arm64 host with the Debian multiarch layout,
// discovery finds the aarch64 libssl — the old hard-coded x86_64 path is gone.
func TestDiscoverLibsslAarch64(t *testing.T) {
	want := "/usr/lib/aarch64-linux-gnu/libssl.so.3"
	got, err := discoverLibssl("arm64", nil, existsSet(want))
	if err != nil {
		t.Fatalf("discover arm64: %v", err)
	}
	if got != want {
		t.Fatalf("discover arm64 = %q, want %q", got, want)
	}
}

func TestDiscoverLibsslAmd64AndDistroFallbacks(t *testing.T) {
	cases := []struct {
		name, goarch, want string
	}{
		{"debian amd64", "amd64", "/usr/lib/x86_64-linux-gnu/libssl.so.3"},
		{"rhel lib64", "amd64", "/usr/lib64/libssl.so.3"},
		{"alpine usr lib", "arm64", "/usr/lib/libssl.so.3"},
		{"openssl 1.1 fallback", "amd64", "/usr/lib/x86_64-linux-gnu/libssl.so.1.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := discoverLibssl(tc.goarch, nil, existsSet(tc.want))
			if err != nil {
				t.Fatalf("discover: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// OpenSSL 3 wins over 1.1 when both are installed.
func TestDiscoverLibsslPrefersSo3(t *testing.T) {
	so3 := "/usr/lib/aarch64-linux-gnu/libssl.so.3"
	so11 := "/usr/lib/aarch64-linux-gnu/libssl.so.1.1"
	got, err := discoverLibssl("arm64", nil, existsSet(so3, so11))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if got != so3 {
		t.Fatalf("got %q, want the .so.3 to win", got)
	}
}

// The ldconfig cache is consulted first — it finds non-standard prefixes the
// candidate list does not know about.
func TestDiscoverLibsslViaLdconfig(t *testing.T) {
	out := []byte(`	libstdc++.so.6 (libc6,AArch64) => /usr/lib/aarch64-linux-gnu/libstdc++.so.6
	libssl.so.3 (libc6,AArch64) => /opt/custom/lib/libssl.so.3
	libssl.so.1.1 (libc6,AArch64) => /usr/lib/aarch64-linux-gnu/libssl.so.1.1`)
	ld := func() ([]byte, error) { return out, nil }
	got, err := discoverLibssl("arm64", ld, existsSet("/opt/custom/lib/libssl.so.3"))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if got != "/opt/custom/lib/libssl.so.3" {
		t.Fatalf("got %q, want the ldconfig-cache path", got)
	}
}

func TestDiscoverLibgnutlsViaLdconfig(t *testing.T) {
	out := []byte(`	libstdc++.so.6 (libc6,AArch64) => /usr/lib/aarch64-linux-gnu/libstdc++.so.6
	libgnutls.so.30 (libc6,AArch64) => /opt/custom/lib/libgnutls.so.30
	libgnutls.so.28 (libc6,AArch64) => /usr/lib/aarch64-linux-gnu/libgnutls.so.28`)
	ld := func() ([]byte, error) { return out, nil }
	got, err := discoverLibgnutls("arm64", ld, existsSet("/opt/custom/lib/libgnutls.so.30"))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if got != "/opt/custom/lib/libgnutls.so.30" {
		t.Fatalf("got %q, want the ldconfig-cache path", got)
	}
}

func TestDiscoverTLSProbeLibrariesFindsOpenSSLAndGnuTLS(t *testing.T) {
	libssl := "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	libgnutls := "/usr/lib/x86_64-linux-gnu/libgnutls.so.30"
	got, err := discoverTLSProbeLibraries("amd64", "", nil, existsSet(libssl, libgnutls))
	if err != nil {
		t.Fatalf("discover TLS probe libraries: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d libraries, want 2: %#v", len(got), got)
	}
	openssl, ok := probeLibraryByName(got, "openssl")
	if !ok {
		t.Fatalf("OpenSSL-compatible descriptor missing: %#v", got)
	}
	if openssl.path != libssl || openssl.writeSymbol != "SSL_write" || openssl.readSymbol != "SSL_read" {
		t.Fatalf("bad OpenSSL-compatible descriptor: %#v", openssl)
	}
	gnutls, ok := probeLibraryByName(got, "gnutls")
	if !ok {
		t.Fatalf("GnuTLS descriptor missing: %#v", got)
	}
	if gnutls.path != libgnutls || gnutls.writeSymbol != "gnutls_record_send" || gnutls.readSymbol != "gnutls_record_recv" {
		t.Fatalf("bad GnuTLS descriptor: %#v", gnutls)
	}
}

func TestDiscoverTLSProbeLibrariesUsesLibsslOverrideAndGnuTLS(t *testing.T) {
	override := "/opt/boringssl/lib/libssl.so"
	libgnutls := "/usr/lib/aarch64-linux-gnu/libgnutls.so.30"
	got, err := discoverTLSProbeLibraries("arm64", override, nil, existsSet(libgnutls))
	if err != nil {
		t.Fatalf("discover TLS probe libraries: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d libraries, want 2: %#v", len(got), got)
	}
	openssl, ok := probeLibraryByName(got, "openssl")
	if !ok {
		t.Fatalf("OpenSSL-compatible descriptor missing: %#v", got)
	}
	if openssl.path != override {
		t.Fatalf("OpenSSL-compatible override path = %q, want %q", openssl.path, override)
	}
	gnutls, ok := probeLibraryByName(got, "gnutls")
	if !ok {
		t.Fatalf("GnuTLS descriptor missing: %#v", got)
	}
	if gnutls.path != libgnutls {
		t.Fatalf("GnuTLS path = %q, want %q", gnutls.path, libgnutls)
	}
}

func TestDiscoverTLSProbeLibrariesFailureMentionsBothStacks(t *testing.T) {
	ld := func() ([]byte, error) { return nil, errors.New("no ldconfig") }
	_, err := discoverTLSProbeLibraries("arm64", "", ld, existsSet())
	if err == nil {
		t.Fatal("want an error when no supported TLS library is found")
	}
	for _, frag := range []string{"libssl", "libgnutls", "PROBECTL_EBPF_LIBSSL", "arm64"} {
		if !strings.Contains(err.Error(), frag) {
			t.Errorf("error should mention %q: %v", frag, err)
		}
	}
}

func probeLibraryByName(libs []tlsProbeLibrary, name string) (tlsProbeLibrary, bool) {
	for _, lib := range libs {
		if lib.name == name {
			return lib, true
		}
	}
	return tlsProbeLibrary{}, false
}

// A failing/absent ldconfig degrades to the candidate list; nothing found is a
// loud error that names what was tried and the override knob.
func TestDiscoverLibsslFailureIsLoud(t *testing.T) {
	ld := func() ([]byte, error) { return nil, errors.New("no ldconfig") }
	_, err := discoverLibssl("arm64", ld, existsSet())
	if err == nil {
		t.Fatal("want an error when nothing is found")
	}
	for _, frag := range []string{"PROBECTL_EBPF_LIBSSL", "aarch64-linux-gnu", "arm64"} {
		if !strings.Contains(err.Error(), frag) {
			t.Errorf("error should mention %q: %v", frag, err)
		}
	}
}

// discoverLibsslDefault (the production wiring, called from the -tags ebpf
// source) is exercised against the real test host: whatever the host has, it
// must return either a usable path or the loud, actionable error — and this
// reference keeps the default (untagged) lint honest about it being used.
func TestDiscoverLibsslDefaultIsLoudEitherWay(t *testing.T) {
	p, err := discoverLibsslDefault()
	if err == nil {
		if p == "" {
			t.Fatal("discoverLibsslDefault returned an empty path with a nil error")
		}
		return
	}
	if !strings.Contains(err.Error(), "PROBECTL_EBPF_LIBSSL") {
		t.Errorf("failure must mention the override knob: %v", err)
	}
}

// The attach-failure counter rides the same Stats surface as drops — the gap
// is a metric, never silent (U-015).
func TestAggregatorL7AttachFailureCounter(t *testing.T) {
	a := NewAggregator()
	if got := a.Stats().L7AttachFailures; got != 0 {
		t.Fatalf("initial L7AttachFailures = %d", got)
	}
	a.RecordL7AttachFailure()
	if got := a.Stats().L7AttachFailures; got != 1 {
		t.Fatalf("L7AttachFailures = %d, want 1", got)
	}
}
