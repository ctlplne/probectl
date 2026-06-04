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
