// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
)

// ParseCertificate parses one DER-encoded certificate through the crypto
// boundary so ingestion/control packages never call x509 primitives directly.
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

// CertKeyInfo reports a certificate's public-key algorithm and strength in bits.
// It lives in internal/crypto so the rest of the codebase (e.g. the S27 TLS/cert
// observer) can inspect key strength WITHOUT importing crypto/rsa|ecdsa|ed25519
// directly — the FIPS import guard keeps those primitives here.
func CertKeyInfo(cert *x509.Certificate) (keyType string, keyBits int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return cert.PublicKeyAlgorithm.String(), 0
	}
}
