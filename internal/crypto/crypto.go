// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// Provider is probectl's cryptographic abstraction. Every cryptographic operation
// in the product routes through a Provider so a FIPS 140-3 validated module can
// be compiled in later (docs/guardrails.md G7-3). internal/crypto is the only
// package that imports crypto primitive packages.
type Provider interface {
	// Hash returns a SHA-256 digest of data.
	Hash(data []byte) []byte
	// Random returns n cryptographically secure random bytes.
	Random(n int) ([]byte, error)
	// Encrypt seals plaintext with a 32-byte key using AES-256-GCM, binding the
	// additional authenticated data aad. The 96-bit nonce is generated internally
	// and prepended to the returned ciphertext.
	Encrypt(key, plaintext, aad []byte) ([]byte, error)
	// Decrypt opens AES-256-GCM ciphertext produced by Encrypt.
	Decrypt(key, ciphertext, aad []byte) ([]byte, error)
	// Sign returns an HMAC-SHA256 of data under key.
	Sign(key, data []byte) []byte
	// Verify checks an HMAC-SHA256 in constant time.
	Verify(key, data, mac []byte) bool
}

// KeySize is the required symmetric key length for Encrypt/Decrypt (AES-256).
const KeySize = 32

// Default is the standard-library Provider, used unless a FIPS module is compiled
// in (S-EE1).
var Default Provider = stdProvider{}

type stdProvider struct{}

func (stdProvider) Hash(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func (stdProvider) Random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("crypto: random: %w", err)
	}
	return b, nil
}

func (stdProvider) Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	// NewGCMWithRandomNonce generates a fresh 96-bit nonce for every message and
	// prepends it to the ciphertext — the same wire layout the earlier
	// caller-managed nonce produced, so data sealed by previous builds still
	// opens. The nonce argument must be nil (the AEAD owns nonce selection).
	// This is the FIPS-approved GCM path: fips140=only rejects a caller-chosen
	// IV (docs/guardrails.md G7-3).
	return gcm.Seal(nil, nil, plaintext, aad), nil
}

func (stdProvider) Decrypt(key, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	// newGCM is NewGCMWithRandomNonce: it reads the 12-byte nonce it prepended
	// from the front of the ciphertext, so the nonce argument is empty. This
	// also opens ciphertext written by earlier builds (identical wire layout).
	if len(ciphertext) < gcm.Overhead() {
		return nil, errors.New("crypto: ciphertext too short")
	}
	pt, err := gcm.Open(nil, nil, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	return pt, nil
}

func (stdProvider) Sign(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func (p stdProvider) Verify(key, data, mac []byte) bool {
	return hmac.Equal(mac, p.Sign(key, data))
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: cipher: %w", err)
	}
	// NewGCMWithRandomNonce: the AEAD owns nonce generation, prepending a fresh
	// 96-bit nonce to every ciphertext, so no caller-chosen IV is ever used.
	// GODEBUG=fips140=only rejects a caller-managed GCM nonce, so this is the
	// path a FIPS build must take; the 12-byte-nonce-prefix wire layout is
	// identical to the earlier caller-managed nonce, so ciphertext written by
	// previous builds still opens (RTT-05, docs/guardrails.md G7-3).
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm: %w", err)
	}
	return gcm, nil
}

// Package-level convenience wrappers delegate to Default.

// Hash returns a SHA-256 digest of data.
func Hash(data []byte) []byte { return Default.Hash(data) }

// Random returns n cryptographically secure random bytes.
func Random(n int) ([]byte, error) { return Default.Random(n) }

// UUIDv4 mints a canonical random v4 UUID via the crypto provider (no external
// dependency): 16 secure-random bytes with the version (4) and variant (10x)
// bits set. Used for per-record dedup ids (CORRECT-002) and agent identities.
func UUIDv4() (string, error) {
	b, err := Random(16)
	if err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// Encrypt seals plaintext with key (AES-256-GCM) binding aad.
func Encrypt(key, plaintext, aad []byte) ([]byte, error) { return Default.Encrypt(key, plaintext, aad) }

// Decrypt opens AES-256-GCM ciphertext.
func Decrypt(key, ciphertext, aad []byte) ([]byte, error) {
	return Default.Decrypt(key, ciphertext, aad)
}

// Sign returns an HMAC-SHA256 of data under key.
func Sign(key, data []byte) []byte { return Default.Sign(key, data) }

// Verify checks an HMAC-SHA256 in constant time.
func Verify(key, data, mac []byte) bool { return Default.Verify(key, data, mac) }

// ConstantTimeEqual reports whether a and b are equal, comparing in constant time
// to avoid timing leaks. Used to check a shared secret token (e.g. a GitLab-style
// webhook token) where the sender presents the secret directly rather than an
// HMAC. It lives in internal/crypto so callers never import crypto/subtle or
// crypto/hmac directly (the FIPS import guard).
func ConstantTimeEqual(a, b []byte) bool { return hmac.Equal(a, b) }

// Zeroize best-effort overwrites key material with zeros (KEYS-002). Go's
// garbage collector may copy a slice before this runs and the compiler may not
// guarantee the write survives if the buffer is otherwise dead, so this is
// defense-in-depth — it shrinks the window a plaintext DEK/KEK lingers in the
// heap, it does not guarantee erasure. It lives here so callers do not reach
// for crypto primitives directly (the FIPS import guard).
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
