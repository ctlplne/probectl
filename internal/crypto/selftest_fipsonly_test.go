// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/fips140"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// RTT-05 regression: the power-on self-test must boot clean under
// GODEBUG=fips140=only — the FIPS 140-only runtime mode that PANICS on any
// non-approved operation. The POST's HMAC known-answer test once keyed on
// "Jefe" (4 bytes / 32 bits); fips140=only forbids HMAC keys shorter than 112
// bits, so a FIPS control built GOFIPS140=v1.0.0 crashed at startup under
// fips140=only. The fix keys the KAT on an RFC 4231 TC1 20-byte key.
//
// fips140 is read once at process start, so it cannot be toggled from inside a
// running test. These tests therefore re-exec the test binary as a child with
// GODEBUG=fips140=only and run the REAL PowerOnSelfTest there. This is
// hermetic (pure `go test`) and meaningful in BOTH builds: fips140=only
// enforcement is active even in the standard, non-GOFIPS140 build.
const fipsOnlyChildVar = "PROBECTL_POST_FIPSONLY_CHILD"

// shortKATKey is a deliberately-forbidden HMAC key (32 bits < the 112-bit FIPS
// 140-only floor), used only by the non-vacuity child to prove the test would
// actually catch a regression back to a short key.
var shortKATKey = []byte("Jefe")

func TestMain(m *testing.M) {
	// Child entry points: each runs under GODEBUG=fips140=only (set by the
	// parent) and reports via exit code, before the test framework runs.
	switch os.Getenv(fipsOnlyChildVar) {
	case "pass":
		if !fips140.Enforced() {
			fmt.Fprintln(os.Stderr, "child is not running under GODEBUG=fips140=only")
			os.Exit(3)
		}
		if err := PowerOnSelfTest(); err != nil {
			fmt.Fprintf(os.Stderr, "PowerOnSelfTest returned error under fips140=only: %v\n", err)
			os.Exit(1)
		}
		if !Status().SelfTestPassed {
			fmt.Fprintln(os.Stderr, "Status().SelfTestPassed is false after a successful POST")
			os.Exit(1)
		}
		os.Exit(0)
	case "shortkey":
		// Non-vacuity: restore a <112-bit key and confirm the POST PANICS under
		// fips140=only (reaching the line after is itself the failure).
		if !fips140.Enforced() {
			fmt.Fprintln(os.Stderr, "child is not running under GODEBUG=fips140=only")
			os.Exit(3)
		}
		katHMACKey = shortKATKey
		err := PowerOnSelfTest()
		fmt.Fprintf(os.Stderr, "BUG: POST did not panic with a 32-bit HMAC key under fips140=only (err=%v)\n", err)
		os.Exit(0)
	case "cryptoexercise":
		// RTT-05 (full acceptance): the FIPS build must not only BOOT but also
		// OPERATE under fips140=only. Exercise the two internal/crypto paths that
		// would otherwise PANIC there — the GCM envelope seal (a caller-chosen IV
		// is rejected; the fix uses NewGCMWithRandomNonce) and PBKDF2 password
		// hashing with a short, low-entropy password (a raw crypto/hmac call would
		// trip the 112-bit HMAC-key floor; the fix routes through crypto/pbkdf2).
		if !fips140.Enforced() {
			fmt.Fprintln(os.Stderr, "child is not running under GODEBUG=fips140=only")
			os.Exit(3)
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			fmt.Fprintf(os.Stderr, "rand: %v\n", err)
			os.Exit(1)
		}
		ct, err := Encrypt(key, []byte("probe-plaintext"), []byte("probe-aad"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Encrypt under fips140=only: %v\n", err)
			os.Exit(1)
		}
		pt, err := Decrypt(key, ct, []byte("probe-aad"))
		if err != nil || string(pt) != "probe-plaintext" {
			fmt.Fprintf(os.Stderr, "Decrypt under fips140=only: %v (pt=%q)\n", err, pt)
			os.Exit(1)
		}
		// A deliberately short user password: raw crypto/hmac keyed on it would
		// panic under fips140=only; crypto/pbkdf2 treats it as a password.
		rec, err := HashPassword("pw")
		if err != nil {
			fmt.Fprintf(os.Stderr, "HashPassword under fips140=only: %v\n", err)
			os.Exit(1)
		}
		if !VerifyPassword(rec, "pw") || VerifyPassword(rec, "wrong") {
			fmt.Fprintln(os.Stderr, "VerifyPassword gave the wrong answer under fips140=only")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runFIPSOnlyChild re-execs this test binary with GODEBUG=fips140=only and the
// given child mode, returning the child's combined output and run error (nil
// == exit 0).
func runFIPSOnlyChild(t *testing.T, mode string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", "^$")
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		// Strip any inherited GODEBUG / child marker so ours is authoritative.
		if strings.HasPrefix(kv, "GODEBUG=") || strings.HasPrefix(kv, fipsOnlyChildVar+"=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "GODEBUG=fips140=only", fipsOnlyChildVar+"="+mode)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestPowerOnSelfTestUnderFIPS140Only is the RTT-05 regression. The real
// PowerOnSelfTest must pass (no panic) under GODEBUG=fips140=only.
func TestPowerOnSelfTestUnderFIPS140Only(t *testing.T) {
	out, err := runFIPSOnlyChild(t, "pass")
	if err != nil {
		t.Fatalf("PowerOnSelfTest must pass under GODEBUG=fips140=only, but the child failed: %v\n%s", err, out)
	}
	if strings.Contains(out, "shorter than 112 bits") {
		t.Fatalf("POST hit the FIPS 140-only short-key panic:\n%s", out)
	}
}

// TestPowerOnSelfTestFIPS140OnlyNonVacuous proves the fips140=only check above
// is not vacuous: with a 32-bit HMAC key restored, the POST must PANIC under
// fips140=only with the exact finding. If this ever stops panicking, the guard
// has rotted and the pass test proves nothing.
func TestPowerOnSelfTestFIPS140OnlyNonVacuous(t *testing.T) {
	out, err := runFIPSOnlyChild(t, "shortkey")
	if err == nil {
		t.Fatalf("non-vacuity: a 32-bit HMAC key did NOT fail the POST under fips140=only:\n%s", out)
	}
	if !strings.Contains(out, "shorter than 112 bits") {
		t.Fatalf("non-vacuity: expected the FIPS 140-only short-key panic, got:\n%s", out)
	}
}

// TestCryptoEnvelopeAndPasswordUnderFIPS140Only proves RTT-05's full acceptance:
// the internal/crypto envelope (GCM seal/open) and PBKDF2 password hashing both
// OPERATE under GODEBUG=fips140=only, not just at boot. Before the fix the GCM
// caller-chosen IV and the raw-crypto/hmac PBKDF2 each panicked there, so a FIPS
// control would crash on the first secret-encrypt or login.
func TestCryptoEnvelopeAndPasswordUnderFIPS140Only(t *testing.T) {
	out, err := runFIPSOnlyChild(t, "cryptoexercise")
	if err != nil {
		t.Fatalf("envelope + password must operate under GODEBUG=fips140=only, child failed: %v\n%s", err, out)
	}
	if strings.Contains(out, "shorter than 112 bits") || strings.Contains(out, "caller") {
		t.Fatalf("a fips140=only panic leaked into the crypto exercise:\n%s", out)
	}
}
