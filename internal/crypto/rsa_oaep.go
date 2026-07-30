// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// ErrUnwrapUnavailable distinguishes a public-only wrapping provider from a
// broken private-key provider. Steady-state IR attribution writers are
// intentionally constructed public-only and therefore cannot decrypt what
// they seal.
var ErrUnwrapUnavailable = errors.New("crypto: key provider has no unwrap capability")

// RSAOAEPKeyProvider implements KeyProvider with RSA-OAEP-SHA256. A provider
// constructed from a public key can wrap per-record DEKs but cannot unwrap
// them; investigation code must explicitly construct a private-key provider.
//
// RSA primitives remain inside internal/crypto (guardrail 3). Callers depend
// only on the generic KeyProvider interface used by Envelope.
type RSAOAEPKeyProvider struct {
	keyID string
	pub   *rsa.PublicKey
	priv  *rsa.PrivateKey
}

// Destroy removes this provider's private unwrap capability. Investigation
// callers invoke it as soon as one bounded open completes; routine wrapping
// providers never need it. The private PEM bytes are wiped by the caller before
// this method runs, and dropping these references prevents accidental reuse.
func (p *RSAOAEPKeyProvider) Destroy() {
	if p == nil {
		return
	}
	p.priv = nil
	p.pub = nil
	p.keyID = ""
}

// NewRSAOAEPWrapProviderPEM returns a public-only DEK wrapping provider.
func NewRSAOAEPWrapProviderPEM(publicPEM []byte) (*RSAOAEPKeyProvider, error) {
	pub, err := parseRSAOAEPPublicPEM(publicPEM)
	if err != nil {
		return nil, err
	}
	return &RSAOAEPKeyProvider{keyID: rsaOAEPKeyID(pub), pub: pub}, nil
}

// NewRSAOAEPKeyProviderPEM returns a wrapping and unwrapping provider from a
// PKCS#8 or PKCS#1 RSA private key.
func NewRSAOAEPKeyProviderPEM(privatePEM []byte) (*RSAOAEPKeyProvider, error) {
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return nil, errors.New("crypto: invalid RSA private-key PEM")
	}
	var priv *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse RSA PKCS#8 private key: %w", err)
		}
		var ok bool
		priv, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("crypto: private key is not RSA")
		}
	case "RSA PRIVATE KEY":
		var err error
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse RSA PKCS#1 private key: %w", err)
		}
	default:
		return nil, fmt.Errorf("crypto: unsupported RSA private-key PEM block %q", block.Type)
	}
	if err := validateRSAOAEPKey(&priv.PublicKey); err != nil {
		return nil, err
	}
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("crypto: validate RSA private key: %w", err)
	}
	return &RSAOAEPKeyProvider{
		keyID: rsaOAEPKeyID(&priv.PublicKey),
		pub:   &priv.PublicKey,
		priv:  priv,
	}, nil
}

// GenerateRSAOAEPKeyPEM creates an operator-owned RSA-3072 keypair. The
// private half is PKCS#8 PEM and the public half is PKIX PEM.
func GenerateRSAOAEPKeyPEM() (privatePEM, publicPEM []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: generate RSA-3072 key: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: marshal RSA private key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: marshal RSA public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), nil
}

// KeyID returns a content-derived, non-secret identity for the public key.
func (p *RSAOAEPKeyProvider) KeyID() string {
	if p == nil {
		return ""
	}
	return p.keyID
}

// WrapKey encrypts a DEK with RSA-OAEP-SHA256 and binds the key identity as
// the OAEP label.
func (p *RSAOAEPKeyProvider) WrapKey(_ context.Context, dek []byte) ([]byte, error) {
	if p == nil || p.pub == nil {
		return nil, errors.New("crypto: RSA wrapping provider is unavailable")
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, p.pub, dek, []byte(p.keyID))
	if err != nil {
		return nil, fmt.Errorf("crypto: RSA-OAEP wrap: %w", err)
	}
	return wrapped, nil
}

// UnwrapKey decrypts a DEK only when this provider was explicitly constructed
// with the matching private key.
func (p *RSAOAEPKeyProvider) UnwrapKey(_ context.Context, keyID string, wrapped []byte) ([]byte, error) {
	if p == nil || p.priv == nil {
		return nil, ErrUnwrapUnavailable
	}
	if keyID != p.keyID {
		return nil, fmt.Errorf("crypto: RSA-OAEP key id %q is unavailable", keyID)
	}
	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, p.priv, wrapped, []byte(p.keyID))
	if err != nil {
		return nil, fmt.Errorf("crypto: RSA-OAEP unwrap: %w", err)
	}
	return dek, nil
}

func parseRSAOAEPPublicPEM(publicPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicPEM)
	if block == nil {
		return nil, errors.New("crypto: invalid RSA public-key PEM")
	}
	var pub *rsa.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse RSA PKIX public key: %w", err)
		}
		var ok bool
		pub, ok = parsed.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("crypto: public key is not RSA")
		}
	case "RSA PUBLIC KEY":
		var err error
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse RSA PKCS#1 public key: %w", err)
		}
	default:
		return nil, fmt.Errorf("crypto: unsupported RSA public-key PEM block %q", block.Type)
	}
	if err := validateRSAOAEPKey(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

func validateRSAOAEPKey(pub *rsa.PublicKey) error {
	if pub == nil || pub.N == nil || pub.E < 3 {
		return errors.New("crypto: invalid RSA public key")
	}
	if pub.N.BitLen() < 3072 {
		return fmt.Errorf("crypto: RSA-OAEP key must be at least 3072 bits, got %d", pub.N.BitLen())
	}
	return nil
}

func rsaOAEPKeyID(pub *rsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return "rsa-oaep-sha256:" + hex.EncodeToString(Hash(der))
}
