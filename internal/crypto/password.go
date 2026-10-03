// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Password hashing (S-T1): PBKDF2-HMAC-SHA256, routed through the standard
// library's FIPS 140-3 validated module (crypto/pbkdf2) while staying inside
// internal/crypto (docs/guardrails.md G7-3). PBKDF2 is chosen over
// argon2/bcrypt deliberately: it is the KDF a FIPS 140-3 validated module
// provides (SP 800-132), so the FIPS build swaps the implementation without
// changing the stored format. Iterations follow the OWASP 2023+ recommendation
// for PBKDF2-SHA256.
//
// Using crypto/pbkdf2 rather than driving crypto/hmac by hand is what keeps the
// FIPS build sound under GODEBUG=fips140=only: the module treats the password
// as a password (a low-entropy KDF input is expected), so a short user password
// does NOT trip the 112-bit HMAC key floor that a raw crypto/hmac call would
// PANIC on. It still enforces the SP 800-132 128-bit salt floor, returning an
// error (never a panic) for a short salt — and HashPassword always mints a
// 16-byte salt, so real hashing clears that floor (RTT-05).

const (
	pbkdf2Iterations = 600_000
	pbkdf2SaltSize   = 16
	pbkdf2KeySize    = 32
)

// pbkdf2Key derives a key per RFC 2898 §5.2 using PBKDF2-HMAC-SHA256 from the
// validated module. It returns an error (fail closed) rather than panicking
// when the module rejects an input under FIPS 140-only mode (e.g. a salt
// shorter than 128 bits).
func pbkdf2Key(password, salt []byte, iter, keyLen int) ([]byte, error) {
	dk, err := pbkdf2.Key(sha256.New, string(password), salt, iter, keyLen)
	if err != nil {
		return nil, fmt.Errorf("crypto: pbkdf2: %w", err)
	}
	return dk, nil
}

// HashPassword derives a versioned, self-describing password record:
// pbkdf2$sha256$<iter>$<b64 salt>$<b64 dk>. The parameters ride in the record
// so they can be raised later without invalidating existing credentials.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("crypto: empty password")
	}
	salt, err := Random(pbkdf2SaltSize)
	if err != nil {
		return "", err
	}
	dk, err := pbkdf2Key([]byte(password), salt, pbkdf2Iterations, pbkdf2KeySize)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2$sha256$%d$%s$%s",
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk)), nil
}

// VerifyPassword reports whether password matches the stored record, in
// constant time over the derived key. Malformed records verify false, never
// panic (fail closed).
func VerifyPassword(record, password string) bool {
	parts := strings.Split(record, "$")
	if len(parts) != 5 || parts[0] != "pbkdf2" || parts[1] != "sha256" || password == "" {
		return false
	}
	iter, err := strconv.Atoi(parts[2])
	if err != nil || iter < 1 || iter > 10_000_000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2Key([]byte(password), salt, iter, len(want))
	if err != nil {
		return false
	}
	return ConstantTimeEqual(got, want)
}
