package crypto

import (
	"crypto/sha1" //nolint:gosec // SHA1 here is a certificate FINGERPRINT identifier (the abuse.ch SSLBL / CT-log scheme), never a security primitive.
	"crypto/x509"
	"encoding/hex"
)

// CertSHA1 returns the lowercase hex SHA1 fingerprint of a certificate's DER
// encoding — the identifier scheme abuse.ch SSLBL uses for malicious-server-cert
// IOCs (S28). It lives in internal/crypto so the threat plane can fingerprint a
// captured leaf WITHOUT importing crypto/sha1 directly (the FIPS import guard keeps
// hash primitives here). SHA1 is used ONLY as a non-secret content identifier to
// match an external feed's scheme — not for any integrity or signature decision.
func CertSHA1(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha1.Sum(cert.Raw) //nolint:gosec // fingerprint identifier (see package doc), not a security primitive
	return hex.EncodeToString(sum[:])
}
