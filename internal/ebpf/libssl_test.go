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
