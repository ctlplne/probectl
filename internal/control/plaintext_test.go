package control

import (
	"strings"
	"testing"
)

// WIRE-004: TLS is the default — a non-loopback plaintext listener REFUSES to
// start without the explicit opt-in; loopback (local dev) and the opt-in
// (behind a TLS-terminating ingress) are the only ways through.
func TestPlaintextTLSDefault(t *testing.T) {
	refused := []string{":8080", "0.0.0.0:8080", "10.0.0.5:8080", "[::]:8080", "control.internal:8080"}
	for _, addr := range refused {
		err := plaintextAllowed(addr, false)
		if err == nil {
			t.Errorf("plaintext on %q without opt-in must REFUSE", addr)
			continue
		}
		if !strings.Contains(err.Error(), "PROBECTL_ALLOW_PLAINTEXT_HTTP") {
			t.Errorf("refusal must name the opt-in: %v", err)
		}
	}
	for _, addr := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080", "127.0.0.5:9999"} {
		if err := plaintextAllowed(addr, false); err != nil {
			t.Errorf("loopback %q must be allowed for local dev: %v", addr, err)
		}
	}
	if err := plaintextAllowed("0.0.0.0:8080", true); err != nil {
		t.Errorf("explicit opt-in must allow (behind-ingress posture): %v", err)
	}
}
