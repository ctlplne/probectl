// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

// Agent CA hierarchy (Sprint 11, ADR docs/adr/agent-enrollment.md):
//
//	root (10y, MaxPathLen=1, key exportable for offline custody)
//	  └─ issuing intermediate (1y, MaxPathLenZero; sealed at rest)
//	       └─ leaf SVIDs (24h, SPIFFE URI SAN, client-auth only, from CSR)
//
// The dev/test CA in certgen.go stays for dev stacks; THIS is the production
// issuance chain behind agent enrollment.

// GenerateRootCA creates the agent ROOT: it signs intermediates only
// (MaxPathLen=1), never leaves. Its key is exported once at init for offline
// custody and is not required at runtime.
func GenerateRootCA(commonName string, ttl time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate root key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"probectl"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1, // exactly one intermediate below
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("crypto: create root cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, certPEM: pemEncode("CERTIFICATE", der)}, nil
}

// IssueIntermediate signs an issuing intermediate under ca (the root). The
// intermediate signs LEAVES only (MaxPathLenZero).
func (ca *CA) IssueIntermediate(commonName string, ttl time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate intermediate key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"probectl"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("crypto: create intermediate cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, certPEM: pemEncode("CERTIFICATE", der)}, nil
}

// KeyPEM exports the CA private key (root: offline custody at init;
// intermediate: sealed via tenantcrypto before storage — NEVER stored plain).
func (ca *CA) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal ca key: %w", err)
	}
	return pemEncode("EC PRIVATE KEY", der), nil
}

// LoadCA reconstructs a CA from PEM material (the unsealed intermediate).
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("crypto: ca cert PEM malformed")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse ca cert: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("crypto: ca key PEM malformed")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse ca key: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("crypto: certificate is not a CA")
	}
	return &CA{cert: cert, key: key, certPEM: pemEncode("CERTIFICATE", cb.Bytes)}, nil
}

// Cert exposes the CA certificate (chain verification, expiry checks).
func (ca *CA) Cert() *x509.Certificate { return ca.cert }

// CreateCSR generates a fresh P-256 key + a CSR for it on the AGENT side —
// the private key never leaves the machine. Identity (SPIFFE SAN) is decided
// by the SERVER from the enrollment token, never requested by the agent.
func CreateCSR(commonName string) (csrPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: generate agent key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName, Organization: []string{"probectl-agent"}},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: create csr: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pemEncode("CERTIFICATE REQUEST", der), pemEncode("EC PRIVATE KEY", keyDER), nil
}

// SignCSR issues a leaf SVID from an agent CSR. The SERVER controls
// everything security-relevant: the SPIFFE URI SAN (tenant+agent binding),
// client-auth-only EKU, and the TTL — only the PUBLIC KEY is taken from the
// CSR; requested names/extensions are deliberately ignored.
func (ca *CA) SignCSR(csrPEM []byte, spiffeURI string, ttl time.Duration) ([]byte, *big.Int, error) {
	b, _ := pem.Decode(csrPEM)
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, nil, fmt.Errorf("crypto: csr PEM malformed")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("crypto: csr signature (proof of key possession): %w", err)
	}
	u, err := url.Parse(spiffeURI)
	if err != nil || u.Scheme != "spiffe" {
		return nil, nil, fmt.Errorf("crypto: invalid spiffe uri %q", spiffeURI)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: csr.Subject.CommonName, Organization: []string{"probectl"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: sign csr: %w", err)
	}
	return pemEncode("CERTIFICATE", der), serial, nil
}

// ECDSASignPEM signs data (hashed) with a PEM EC private key — the agent's
// rotation proof-of-possession: the CSR is signed with the CURRENT key.
func ECDSASignPEM(keyPEM, data []byte) ([]byte, error) {
	b, _ := pem.Decode(keyPEM)
	if b == nil {
		return nil, fmt.Errorf("crypto: key PEM malformed")
	}
	key, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse ec key: %w", err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, Hash(data))
	if err != nil {
		return nil, fmt.Errorf("crypto: sign: %w", err)
	}
	return sig, nil
}

// ECDSAVerifyCert verifies an ECDSASignPEM signature against a certificate's
// public key — the server side of the rotation proof.
func ECDSAVerifyCert(cert *x509.Certificate, data, sig []byte) error {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("crypto: certificate key is not ECDSA")
	}
	if !ecdsa.VerifyASN1(pub, Hash(data), sig) {
		return fmt.Errorf("crypto: rotation proof signature invalid")
	}
	return nil
}
