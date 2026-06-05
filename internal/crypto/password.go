package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Password hashing (S-T1): PBKDF2-HMAC-SHA256, implemented here so every
// primitive call stays inside internal/crypto (CLAUDE.md §7 guardrail 3).
// PBKDF2 is chosen over argon2/bcrypt deliberately: it is the KDF a FIPS
// 140-3 validated module provides (SP 800-132), so the FIPS build swaps the
// implementation without changing the stored format. Iterations follow the
// OWASP 2023+ recommendation for PBKDF2-SHA256.

const (
	pbkdf2Iterations = 600_000
	pbkdf2SaltSize   = 16
	pbkdf2KeySize    = 32
)

// pbkdf2Key derives a key per RFC 2898 §5.2 using HMAC-SHA256.
func pbkdf2Key(password, salt []byte, iter, keyLen int) []byte {
	prf := func(data []byte) []byte {
		mac := hmac.New(sha256.New, password)
		mac.Write(data)
		return mac.Sum(nil)
	}
	hLen := sha256.Size
	blocks := (keyLen + hLen - 1) / hLen
	dk := make([]byte, 0, blocks*hLen)
	buf := make([]byte, 4)
	for block := 1; block <= blocks; block++ {
		buf[0], buf[1], buf[2], buf[3] = byte(block>>24), byte(block>>16), byte(block>>8), byte(block)
		u := prf(append(append([]byte{}, salt...), buf...))
		t := append([]byte{}, u...)
		for i := 1; i < iter; i++ {
			u = prf(u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
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
	dk := pbkdf2Key([]byte(password), salt, pbkdf2Iterations, pbkdf2KeySize)
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
	got := pbkdf2Key([]byte(password), salt, iter, len(want))
	return ConstantTimeEqual(got, want)
}
