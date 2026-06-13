// SPDX-License-Identifier: LicenseRef-probectl-TBD

package enroll

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
)

// TestSealCAKeyRefusesPlaintext: KEYS-003. The agent-CA intermediate key must
// never be persisted as keyless-dev plaintext. With no envelope key configured
// tenantcrypto.Seal passes the value through unchanged (no scheme prefix), and
// sealCAKey must REFUSE it — `agent-ca init` is gated behind a configured
// envelope key. With a key configured it returns a scheme-prefixed value.
func TestSealCAKeyRefusesPlaintext(t *testing.T) {
	ctx := context.Background()
	interKey := []byte("-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----\n")

	// 1. No primary sealer (keyless dev): plaintext passthrough → REFUSED.
	tenantcrypto.Reset()
	t.Cleanup(tenantcrypto.Reset)
	if _, err := sealCAKey(ctx, interKey); err == nil {
		t.Fatal("sealCAKey must refuse to persist a plaintext CA key when no envelope key is configured (KEYS-003)")
	} else if !strings.Contains(err.Error(), "plaintext") {
		t.Errorf("error should explain the plaintext refusal, got: %v", err)
	}

	// 2. A configured deployment envelope key: a scheme-prefixed sealed value.
	kek := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	sealer, err := tenantcrypto.NewEnvelopeSealer("test", kek)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	sealed, err := sealCAKey(ctx, interKey)
	if err != nil {
		t.Fatalf("sealCAKey with a configured key must succeed: %v", err)
	}
	if !tenantcrypto.HasScheme(sealed) {
		t.Errorf("sealed CA key carries no scheme prefix: %q", sealed)
	}
	if strings.HasPrefix(sealed, string(interKey)) {
		t.Error("sealed CA key must not be the plaintext")
	}
}
