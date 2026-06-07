package tenantcrypto

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// LoadOrGenerateKeyFile makes at-rest encryption the DEFAULT, not an opt-in
// (SEC-002): it returns the base64 KEK stored at path, generating and
// persisting one (0600, parent 0700) on first boot when the file does not
// exist. The shipped compose recipe points PROBECTL_ENVELOPE_KEY_FILE at a
// named volume so a fresh deployment encrypts from its first write — no
// silent keyless passthrough. An explicit PROBECTL_ENVELOPE_KEY (e.g. from a
// KMS/secret manager) always wins over the file; see docs/hardening.md.
//
// generated reports whether this call created the key (callers log it loudly
// — losing the file means sealed values become unreadable, so operators must
// back it up like any key material).
func LoadOrGenerateKeyFile(path string) (kekB64 string, generated bool, err error) {
	if path == "" {
		return "", false, fmt.Errorf("tenantcrypto: empty key file path")
	}
	if b, rerr := os.ReadFile(path); rerr == nil {
		kek := strings.TrimSpace(string(b))
		if derr := validKEK(kek); derr != nil {
			return "", false, fmt.Errorf("tenantcrypto: key file %s: %w", path, derr)
		}
		return kek, false, nil
	} else if !os.IsNotExist(rerr) {
		return "", false, fmt.Errorf("tenantcrypto: read key file: %w", rerr)
	}
	// First boot: generate a 32-byte KEK through internal/crypto (guardrail 3)
	// and persist it atomically with owner-only permissions.
	raw, err := crypto.Random(32)
	if err != nil {
		return "", false, fmt.Errorf("tenantcrypto: generate KEK: %w", err)
	}
	kek := base64.StdEncoding.EncodeToString(raw)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", false, fmt.Errorf("tenantcrypto: key dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(kek+"\n"), 0o600); err != nil {
		return "", false, fmt.Errorf("tenantcrypto: write key file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", false, fmt.Errorf("tenantcrypto: persist key file: %w", err)
	}
	return kek, true, nil
}

// validKEK enforces the 32-byte base64 contract before anything seals with it.
func validKEK(kekB64 string) error {
	raw, err := base64.StdEncoding.DecodeString(kekB64)
	if err != nil {
		return fmt.Errorf("KEK is not valid base64: %w", err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("KEK must decode to 32 bytes, got %d", len(raw))
	}
	return nil
}
