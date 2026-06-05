package crypto

import (
	"crypto/tls"
	"testing"
)

// TestSecureDefaults is the hardening-guide check (S-EE1): the SHIPPED,
// code-level crypto defaults match the documented hardened posture in
// docs/hardening.md §3. If a default regresses, this fails — keeping the doc
// and the binary honest with each other.
func TestSecureDefaults(t *testing.T) {
	cfg := HardenedClientTLSConfig()

	// TLS 1.2 minimum (1.3 negotiated when available).
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("TLS MinVersion = %#x, want >= TLS 1.2 (%#x)", cfg.MinVersion, tls.VersionTLS12)
	}

	// Every offered 1.2 cipher suite is AEAD (GCM or ChaCha20-Poly1305) — no
	// CBC/RC4/3DES. (TLS 1.3 suites are fixed by the stdlib and always AEAD.)
	approvedAEAD := false
	for _, cs := range cfg.CipherSuites {
		switch cs {
		case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
			approvedAEAD = true
		case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			// AEAD, but not FIPS-approved — fine to offer (see below).
		default:
			t.Errorf("non-AEAD/legacy cipher suite offered: %#x", cs)
		}
	}

	// FIPS negotiability: an AES-GCM suite AND P-256 must be present, so a
	// FIPS-mode handshake (which drops ChaCha20 + X25519) still succeeds.
	if !approvedAEAD {
		t.Error("no FIPS-approved AES-GCM cipher suite offered — FIPS handshakes would fail")
	}
	hasP256 := false
	for _, c := range cfg.CurvePreferences {
		if c == tls.CurveP256 {
			hasP256 = true
		}
	}
	if !hasP256 {
		t.Error("P-256 not offered — FIPS-mode key exchange (no X25519) would fail")
	}
}

// TestKeySizeIsAES256 pins the symmetric key size to AES-256 (the documented
// envelope/at-rest strength).
func TestKeySizeIsAES256(t *testing.T) {
	if KeySize != 32 {
		t.Errorf("KeySize = %d, want 32 (AES-256)", KeySize)
	}
}
