// SPDX-License-Identifier: LicenseRef-probectl-TBD

package crypto

import (
	"bytes"
	"crypto/fips140"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync/atomic"
)

// selfTestPassed records the most recent PowerOnSelfTest outcome so the
// status surface can report it without re-running the test (which mints a
// throwaway key each call). It is false until the first successful POST.
var selfTestPassed atomic.Bool

// FIPS 140-3 support (S-EE1, F32). The crypto abstraction (S3) routes every
// primitive through this package, so a FIPS 140-3 validated module compiles in
// transparently: the FIPS build (-tags probectl_fips, built with GOFIPS140)
// swaps the underlying implementations while the Provider API and its outputs
// stay identical. This file owns the runtime status + the power-on self-test.
//
// crypto/fips140 is informational (not a primitive), so it is imported here
// unconditionally; the probectl_fips build TAG (fipsBuildTag) records intent
// — that this artifact is meant to run validated — independent of whether the
// module happens to be enabled.

// FIPSStatus is the compliance/status view (the only surface S-EE1 adds —
// FIPS is a hardening mode, not a feature). Material never appears here.
type FIPSStatus struct {
	// BuildTag is true when compiled as the FIPS distribution artifact.
	BuildTag bool `json:"build_tag"`
	// ModuleActive is true when the Go Cryptographic Module runs in FIPS mode
	// (GOFIPS140 / GODEBUG=fips140=on).
	ModuleActive bool `json:"module_active"`
	// Enforced is true when non-approved algorithms PANIC rather than warn
	// (fips140=only). When false, approved algorithms are used but
	// non-approved ones are still permitted (fips140=on).
	Enforced bool `json:"enforced"`
	// ModuleVersion is the validated module version when active (e.g. "v1.0.0").
	ModuleVersion string `json:"module_version,omitempty"`
	// SelfTestPassed reflects the last PowerOnSelfTest result.
	SelfTestPassed bool `json:"self_test_passed"`
}

// Status reports the FIPS posture (build tag + live module state). It does
// not run the self-test; call PowerOnSelfTest for that.
func Status() FIPSStatus {
	st := FIPSStatus{
		BuildTag:     fipsBuildTag,
		ModuleActive: fips140.Enabled(),
		Enforced:     fips140.Enforced(),
	}
	if st.ModuleActive {
		st.ModuleVersion = fips140.Version()
	}
	st.SelfTestPassed = selfTestPassed.Load()
	return st
}

// RunPowerOnSelfTest is the process-start helper for commands that use
// probectl crypto. It wraps the POST with the uniform fail-closed error and the
// optional structured FIPS posture log.
func RunPowerOnSelfTest(log *slog.Logger) error {
	if err := PowerOnSelfTest(); err != nil {
		return fmt.Errorf("crypto power-on self-test: %w", err)
	}
	LogPowerOnSelfTestStatus(log)
	return nil
}

// LogPowerOnSelfTestStatus reports the live FIPS posture after the POST has
// passed. Nil loggers are intentional for stdout-sensitive commands such as
// backup filters and signing CLIs.
func LogPowerOnSelfTestStatus(log *slog.Logger) {
	if log == nil {
		return
	}
	if st := Status(); st.BuildTag || st.ModuleActive {
		log.Info("crypto self-test passed",
			"fips_build", st.BuildTag,
			"fips_module_active", st.ModuleActive,
			"fips_enforced", st.Enforced,
			"module_version", st.ModuleVersion)
	}
}

// Known-answer test vectors (published, standardized — the transparent-swap
// guarantee is that these hold in EVERY build):
//   - SHA-256("abc")                                   FIPS 180-4
//   - HMAC-SHA-256("Jefe", "what do ya want…")         RFC 4231 TC2
//   - PBKDF2-HMAC-SHA-256("password","salt",1,32)      SP 800-132 vector
var (
	katSHA256Input  = []byte("abc")
	katSHA256Expect = mustHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

	katHMACKey    = []byte("Jefe")
	katHMACData   = []byte("what do ya want for nothing?")
	katHMACExpect = mustHex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

	katPBKDF2Pass   = []byte("password")
	katPBKDF2Salt   = []byte("salt")
	katPBKDF2Expect = mustHex("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("crypto: bad KAT vector: " + err.Error())
	}
	return b
}

// PowerOnSelfTest runs known-answer + operational tests across the primitives
// the Provider exposes, then — in a FIPS-tagged build — asserts the validated
// module is actually active. It returns the first failure; a nil return means
// the crypto stack is healthy and (in the FIPS artifact) running validated.
//
// Call it once at process startup BEFORE serving traffic, and fail closed on
// error: a control plane or agent whose crypto self-test fails must not run.
// The Go module runs its own CAST/integrity checks at init; this POST proves
// the probectl integration end-to-end and catches a FIPS artifact that was
// built without the module enabled.
func PowerOnSelfTest() error {
	p := Default

	// SHA-256 (Hash) — known answer.
	if got := p.Hash(katSHA256Input); !bytes.Equal(got, katSHA256Expect) {
		return fmt.Errorf("crypto POST: SHA-256 KAT failed: got %x", got)
	}

	// HMAC-SHA-256 (Sign/Verify) — known answer + verification round-trip +
	// negative (a tampered MAC must be rejected).
	mac := p.Sign(katHMACKey, katHMACData)
	if !bytes.Equal(mac, katHMACExpect) {
		return fmt.Errorf("crypto POST: HMAC-SHA-256 KAT failed: got %x", mac)
	}
	if !p.Verify(katHMACKey, katHMACData, mac) {
		return fmt.Errorf("crypto POST: HMAC verify rejected a valid MAC")
	}
	bad := append([]byte(nil), mac...)
	bad[0] ^= 0xff
	if p.Verify(katHMACKey, katHMACData, bad) {
		return fmt.Errorf("crypto POST: HMAC verify accepted a tampered MAC")
	}

	// PBKDF2-HMAC-SHA-256 (password KDF, SP 800-132) — known answer.
	if got := pbkdf2Key(katPBKDF2Pass, katPBKDF2Salt, 1, 32); !bytes.Equal(got, katPBKDF2Expect) {
		return fmt.Errorf("crypto POST: PBKDF2-SHA-256 KAT failed: got %x", got)
	}

	// AES-256-GCM (Encrypt/Decrypt) — operational KAT: round-trip recovers the
	// plaintext, the ciphertext is a real transform (not the plaintext), and a
	// tampered AAD / wrong key is rejected (authenticity holds).
	key := bytes.Repeat([]byte{0x42}, KeySize)
	plain := []byte("probectl power-on self-test")
	aad := []byte("post-aad")
	ct, err := p.Encrypt(key, plain, aad)
	if err != nil {
		return fmt.Errorf("crypto POST: AES-GCM encrypt: %w", err)
	}
	if bytes.Contains(ct, plain) {
		return fmt.Errorf("crypto POST: AES-GCM ciphertext leaks plaintext")
	}
	got, err := p.Decrypt(key, ct, aad)
	if err != nil || !bytes.Equal(got, plain) {
		return fmt.Errorf("crypto POST: AES-GCM round-trip failed: %v", err)
	}
	if _, err := p.Decrypt(key, ct, []byte("wrong-aad")); err == nil {
		return fmt.Errorf("crypto POST: AES-GCM accepted a tampered AAD")
	}

	// Ed25519 (license/identity signatures) — operational KAT through the full
	// PEM round-trip: a valid signature verifies, a tampered message and a
	// foreign key are both rejected.
	privPEM, pubPEM, err := GenerateEd25519KeyPEM()
	if err != nil {
		return fmt.Errorf("crypto POST: Ed25519 keygen: %w", err)
	}
	msg := []byte("probectl POST signature")
	sig, err := SignEd25519(privPEM, msg)
	if err != nil {
		return fmt.Errorf("crypto POST: Ed25519 sign: %w", err)
	}
	if ok, err := VerifyEd25519(pubPEM, msg, sig); err != nil || !ok {
		return fmt.Errorf("crypto POST: Ed25519 verify rejected a valid signature: %v", err)
	}
	if ok, _ := VerifyEd25519(pubPEM, []byte("tampered"), sig); ok {
		return fmt.Errorf("crypto POST: Ed25519 verify accepted a tampered message")
	}
	if _, otherPub, err := GenerateEd25519KeyPEM(); err == nil {
		if ok, _ := VerifyEd25519(otherPub, msg, sig); ok {
			return fmt.Errorf("crypto POST: Ed25519 verify accepted a foreign key")
		}
	}

	// DRBG (Random) — sanity: full-length output and two draws differ (the
	// module runs the DRBG health/KAT internally).
	r1, err := Random(32)
	if err != nil || len(r1) != 32 {
		return fmt.Errorf("crypto POST: DRBG draw failed: %v", err)
	}
	if r2, _ := Random(32); bytes.Equal(r1, r2) {
		return fmt.Errorf("crypto POST: DRBG returned identical draws")
	}

	// FIPS artifact fail-closed: a build tagged probectl_fips MUST be running
	// the validated module. Catches an artifact built without GOFIPS140.
	if fipsBuildTag && !fips140.Enabled() {
		return fmt.Errorf("crypto POST: FIPS build (probectl_fips) but the validated module is INACTIVE — build with GOFIPS140=v1.0.0 or set GODEBUG=fips140=on")
	}
	selfTestPassed.Store(true)
	return nil
}
