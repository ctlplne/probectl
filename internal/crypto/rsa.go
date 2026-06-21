// SPDX-License-Identifier: LicenseRef-probectl-TBD

package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// SignRS256 signs data with an RSA private key (PKCS#1 v1.5 over SHA-256) —
// the JWT "RS256" algorithm. The key is PEM ("PRIVATE KEY" PKCS#8 or "RSA
// PRIVATE KEY" PKCS#1). It lives here so callers never touch crypto
// primitives directly (CLAUDE.md §7 guardrail 3); a FIPS provider swaps the
// implementation, not the callers.
//
// Interop note: GCP service-account JWT requires RS256 (PKCS#1 v1.5). New
// INTERNAL signing schemes must use SignRSAPSS instead (FIPS 186-5 / KEYS-001).
func SignRS256(privateKeyPEM, data []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("crypto: no PEM block in private key")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse PKCS#1 key: %w", err)
		}
		key = k
	default:
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse PKCS#8 key: %w", err)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("crypto: private key is not RSA")
		}
		key = rk
	}
	digest := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
}

// SignRSAPSS signs data with an RSA private key using PSS padding and SHA-256
// (FIPS 186-5 compliant — KEYS-001). The salt length equals the hash length
// (PSSSaltLengthEqualsHash). All new INTERNAL RSA signing schemes must call
// this function; SignRS256 (PKCS#1 v1.5) is retained only for the GCP RS256
// JWT interop path which requires the legacy algorithm.
//
// The public key is standard RSA; verify with VerifyRSAPSS.
func SignRSAPSS(privateKeyPEM, data []byte) ([]byte, error) {
	key, err := parseRSAPrivatePEM(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	return rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

// VerifyRSAPSS verifies a PSS signature produced by SignRSAPSS. The public key
// is PEM-encoded ("PUBLIC KEY" PKIX).
func VerifyRSAPSS(publicKeyPEM, data, sig []byte) error {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return errors.New("crypto: no PEM block in public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("crypto: parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("crypto: public key is not RSA")
	}
	digest := sha256.Sum256(data)
	return rsa.VerifyPSS(rsaPub, crypto.SHA256, digest[:], sig,
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

// parseRSAPrivatePEM decodes PEM and returns an *rsa.PrivateKey.
func parseRSAPrivatePEM(privateKeyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("crypto: no PEM block in private key")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse PKCS#1 key: %w", err)
		}
		return k, nil
	default:
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse PKCS#8 key: %w", err)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("crypto: private key is not RSA")
		}
		return rk, nil
	}
}

// GenerateRSAKeyPEM generates an RSA private key and returns it PKCS#8
// PEM-encoded ("PRIVATE KEY"). It lives here so callers (including tests
// that fabricate service-account keys) never touch RSA primitives directly
// (guardrail 3 — the crypto-import gate enforces this repo-wide).
func GenerateRSAKeyPEM(bits int) ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate rsa key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal rsa key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
