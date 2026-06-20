// SPDX-License-Identifier: LicenseRef-probectl-TBD

package crypto

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// CertificatePinPEM returns the hex SHA-256 pin of the first certificate in a
// PEM bundle. Agent enrollment uses this for first-contact trust when the
// control plane serves a self-signed certificate.
func CertificatePinPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", errors.New("crypto: certificate PEM missing")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("crypto: parse certificate for pin: %w", err)
	}
	return hex.EncodeToString(Hash(cert.Raw)), nil
}

// CertificatePinFile reads a PEM certificate file and returns CertificatePinPEM.
func CertificatePinFile(certFile string) (string, error) {
	b, err := os.ReadFile(certFile)
	if err != nil {
		return "", fmt.Errorf("crypto: read certificate for pin: %w", err)
	}
	return CertificatePinPEM(b)
}
