// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Ed25519 operations for the offline license scheme (S-T0) and any future
// detached-signature need. They live here so callers never touch crypto
// primitives directly (CLAUDE.md §7 guardrail 3 — the crypto-import gate
// enforces this repo-wide); a FIPS provider swaps the implementation behind
// the same functions, not the callers.

// GenerateEd25519KeyPEM generates an Ed25519 keypair and returns both halves
// PEM-encoded (PKCS#8 "PRIVATE KEY", PKIX "PUBLIC KEY").
func GenerateEd25519KeyPEM() (privPEM, pubPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: generate ed25519 key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: marshal ed25519 private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: marshal ed25519 public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), nil
}

// ParseEd25519PrivatePEM parses a PKCS#8 PEM Ed25519 private key.
func ParseEd25519PrivatePEM(privPEM []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, errors.New("crypto: no PEM block in ed25519 private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse ed25519 private key: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("crypto: private key is not ed25519")
	}
	return priv, nil
}

// ParseEd25519PublicPEM parses a PKIX PEM Ed25519 public key.
func ParseEd25519PublicPEM(pubPEM []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return nil, errors.New("crypto: no PEM block in ed25519 public key")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse ed25519 public key: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("crypto: public key is not ed25519")
	}
	return pub, nil
}

// PublicPEMFromPrivate derives the PKIX public-key PEM from a PKCS#8 Ed25519
// private-key PEM — used when a signing key is SUPPLIED (env/file) and only
// the private half is on hand, but the public half must be published (e.g. the
// WORM verification key shipped next to the segments).
func PublicPEMFromPrivate(privPEM []byte) ([]byte, error) {
	priv, err := ParseEd25519PrivatePEM(privPEM)
	if err != nil {
		return nil, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("crypto: ed25519 private key has no ed25519 public half")
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal ed25519 public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), nil
}

// LoadOrGenerateEd25519KeyFile loads a PKCS#8 Ed25519 private-key PEM from
// path (deriving the public half); if the file is absent it GENERATES a
// keypair and persists the private PEM (0600, parent dir 0700) so the key is
// STABLE across restarts — the envelope-KEK pattern (tenantcrypto
// .LoadOrGenerateKeyFile) applied to a signing key. generated reports whether
// a new key was minted, so the caller can warn the operator to back it up.
func LoadOrGenerateEd25519KeyFile(path string) (privPEM, pubPEM []byte, generated bool, err error) {
	if path == "" {
		return nil, nil, false, errors.New("crypto: ed25519 key file path is empty")
	}
	switch b, rerr := os.ReadFile(path); {
	case rerr == nil && len(b) > 0:
		pub, perr := PublicPEMFromPrivate(b)
		if perr != nil {
			return nil, nil, false, fmt.Errorf("crypto: ed25519 key file %s: %w", path, perr)
		}
		return b, pub, false, nil
	case rerr != nil && !errors.Is(rerr, os.ErrNotExist):
		return nil, nil, false, fmt.Errorf("crypto: read ed25519 key file %s: %w", path, rerr)
	}
	// Absent (or empty) → generate + persist so the next boot reuses it.
	priv, pub, gerr := GenerateEd25519KeyPEM()
	if gerr != nil {
		return nil, nil, false, gerr
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if mkerr := os.MkdirAll(dir, 0o700); mkerr != nil {
			return nil, nil, false, fmt.Errorf("crypto: create key dir %s: %w", dir, mkerr)
		}
	}
	if werr := os.WriteFile(path, priv, 0o600); werr != nil {
		return nil, nil, false, fmt.Errorf("crypto: persist ed25519 key %s: %w", path, werr)
	}
	return priv, pub, true, nil
}

// SignEd25519 signs data with a PEM-encoded Ed25519 private key.
func SignEd25519(privPEM, data []byte) ([]byte, error) {
	priv, err := ParseEd25519PrivatePEM(privPEM)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, data), nil
}

// VerifyEd25519 verifies a detached signature with a PEM-encoded Ed25519
// public key. It returns true only for a valid signature over exactly data.
func VerifyEd25519(pubPEM, data, sig []byte) (bool, error) {
	pub, err := ParseEd25519PublicPEM(pubPEM)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(pub, data, sig), nil
}
