// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/tls"
	"os"
	"strings"
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

// TestServerListenerTLSFloorMatchesHardeningDoc binds the documented listener
// floor to the enforced one (PLAT-18). hardenedServerTLS — the policy behind
// every probectl-OWNED listener (ServerTLSConfig/ConfigureServerTLS) — is
// TLS 1.3-only, so docs/hardening.md's listener-floor line must state TLS 1.3,
// not the looser "TLS 1.2+". A narrowing of the claim, enforced by a gate: if
// either the code floor regresses or the doc drifts back to "TLS 1.2+" for the
// listener, this fails. (The TLS 1.2+ floor for OUTBOUND clients lives on its
// own doc line and is asserted separately by TestSecureDefaults.)
func TestServerListenerTLSFloorMatchesHardeningDoc(t *testing.T) {
	// Code side: every probectl-owned listener is TLS 1.3-only (WIRE-007).
	if got := hardenedServerTLS().MinVersion; got != tls.VersionTLS13 {
		t.Fatalf("hardenedServerTLS().MinVersion = %#x, want TLS 1.3 (%#x)", got, tls.VersionTLS13)
	}

	// Doc side: the listener-floor line in docs/hardening.md must advertise the
	// SAME floor the code enforces. The test runs from the package directory,
	// so the doc is two levels up.
	const docPath = "../../docs/hardening.md"
	b, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}

	const anchor = "Every listener serves"
	var line string
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.Contains(ln, anchor) {
			line = strings.TrimSpace(ln)
			break
		}
	}
	if line == "" {
		t.Fatalf("listener-floor line (anchored on %q) not found in %s", anchor, docPath)
	}

	// Must state the enforced TLS 1.3 floor...
	if !strings.Contains(line, "TLS 1.3") {
		t.Errorf("listener-floor line does not state the enforced TLS 1.3 floor: %q", line)
	}
	// ...and must NOT advertise the old TLS 1.2+ floor for the listener, which
	// the code does not permit (doc/code mismatch guard).
	if strings.Contains(line, "TLS 1.2+") {
		t.Errorf("listener-floor line still advertises a TLS 1.2+ floor, but the code floor is TLS 1.3: %q", line)
	}
}

// TestKeySizeIsAES256 pins the symmetric key size to AES-256 (the documented
// envelope/at-rest strength).
func TestKeySizeIsAES256(t *testing.T) {
	if KeySize != 32 {
		t.Errorf("KeySize = %d, want 32 (AES-256)", KeySize)
	}
}
