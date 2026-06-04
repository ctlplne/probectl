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
// be compiled in later (CLAUDE.md §7 guardrail 3). internal/crypto is the only
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
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce: %w", err)
	}
	// Seal appends to its first argument, so the nonce is prepended to the output.
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func (stdProvider) Decrypt(key, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("crypto: ciphertext too short")
	}
	nonce, ct := ciphertext[:ns], ciphertext[ns:]
	pt, err := gcm.Open(nil, nonce, ct, aad)
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
	gcm, err := cipher.NewGCM(block)
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
