package ebpf

import (
	"strings"
	"testing"
)

// U-014: a pristine object passes; ANY corruption refuses the load.
func TestVerifyObjectDigestTamper(t *testing.T) {
	obj := []byte{0x7f, 'E', 'L', 'F', 1, 2, 3, 4, 5, 6, 7, 8}
	want := ObjectDigest(obj)

	if err := VerifyObjectDigest("l4flow", obj, want); err != nil {
		t.Fatalf("pristine object refused: %v", err)
	}

	// Corrupt one byte: the load must refuse with a tamper-class error.
	tampered := append([]byte(nil), obj...)
	tampered[5] ^= 0xff
	err := VerifyObjectDigest("l4flow", tampered, want)
	if err == nil {
		t.Fatal("tampered object passed verification")
	}
	if !IsTampered(err) {
		t.Fatalf("want a tamper-class error, got %T: %v", err, err)
	}
	for _, frag := range []string{"l4flow", "mismatch", "refusing"} {
		if !strings.Contains(err.Error(), frag) {
			t.Errorf("error should mention %q: %v", frag, err)
		}
	}

	// Truncation is tampering too.
	if err := VerifyObjectDigest("l4flow", obj[:4], want); err == nil || !IsTampered(err) {
		t.Fatalf("truncated object must refuse: %v", err)
	}
}

// Integrity is never silently skipped: a program missing from the build-time
// manifest refuses to load (fail closed), with the regeneration hint.
func TestVerifyObjectDigestMissingManifestFailsClosed(t *testing.T) {
	err := VerifyObjectDigest("sslsniff", []byte{1, 2, 3}, "")
	if err == nil || !IsTampered(err) {
		t.Fatalf("missing manifest entry must refuse: %v", err)
	}
	if !strings.Contains(err.Error(), "make ebpf-agent") {
		t.Errorf("error should hint at regeneration: %v", err)
	}
}

// The digest is the canonical lowercase hex SHA-256 (what gendigests writes).
func TestObjectDigestShape(t *testing.T) {
	d := ObjectDigest([]byte("x"))
	if len(d) != 64 || strings.ToLower(d) != d {
		t.Fatalf("digest shape: %q", d)
	}
}
