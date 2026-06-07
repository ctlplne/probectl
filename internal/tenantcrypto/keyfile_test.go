package tenantcrypto

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// SEC-002: first boot generates and persists the KEK (0600); the second boot
// loads the SAME key, so values sealed before a restart still open after it.
func TestLoadOrGenerateKeyFileAtRestEncrypts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "envelope.key")

	kek1, generated, err := LoadOrGenerateKeyFile(path)
	if err != nil {
		t.Fatalf("first boot: %v", err)
	}
	if !generated {
		t.Fatal("first boot must report generated=true (operators log + back it up)")
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Fatalf("key file mode = %v, want 0600", fi.Mode().Perm())
		}
	}

	kek2, generated, err := LoadOrGenerateKeyFile(path)
	if err != nil || generated || kek2 != kek1 {
		t.Fatalf("second boot must LOAD the same key: gen=%v err=%v same=%v", generated, err, kek2 == kek1)
	}

	// The generated key drives a real sealer: seal → restart (new sealer from
	// the re-loaded file) → open.
	s1, err := NewEnvelopeSealer("file", kek1)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	sealed, err := s1.Seal(context.Background(), "tenant-a", []byte("hook-secret"), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if sealed == "hook-secret" {
		t.Fatal("PLAINTEXT AT REST: sealed value equals the plaintext")
	}
	s2, err := NewEnvelopeSealer("file", kek2)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.Open(context.Background(), "tenant-a", sealed, nil)
	if err != nil || string(got) != "hook-secret" {
		t.Fatalf("post-restart open: %q err=%v", got, err)
	}
}

// A corrupt/truncated key file must REFUSE (fail closed), not seal weakly.
func TestLoadKeyFileRejectsMalformedAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "envelope.key")
	if err := os.WriteFile(path, []byte("bm90LTMyLWJ5dGVz\n"), 0o600); err != nil { // "not-32-bytes"
		t.Fatal(err)
	}
	if _, _, err := LoadOrGenerateKeyFile(path); err == nil {
		t.Fatal("short KEK must be rejected")
	}
	if err := os.WriteFile(path, []byte("!!not base64!!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrGenerateKeyFile(path); err == nil {
		t.Fatal("non-base64 KEK must be rejected")
	}
}
