package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
)

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
