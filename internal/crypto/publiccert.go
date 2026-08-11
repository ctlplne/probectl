// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PublicCertificateInfo is the non-cryptographic metadata needed by callers
// that audit public certificates without reaching around the crypto boundary.
type PublicCertificateInfo struct {
	FingerprintSHA256 string
	IsCA              bool
	NotBefore         time.Time
	NotAfter          time.Time
	Hosts             []string
}

// InspectPublicCertificatePEM parses exactly one public certificate PEM block.
func InspectPublicCertificatePEM(data []byte) (PublicCertificateInfo, error) {
	certificate, err := parseSingleCertificatePEM(data)
	if err != nil {
		return PublicCertificateInfo{}, err
	}
	hosts := append([]string(nil), certificate.DNSNames...)
	for _, address := range certificate.IPAddresses {
		hosts = append(hosts, address.String())
	}
	return PublicCertificateInfo{
		FingerprintSHA256: hex.EncodeToString(Hash(certificate.Raw)),
		IsCA:              certificate.IsCA,
		NotBefore:         certificate.NotBefore.UTC(),
		NotAfter:          certificate.NotAfter.UTC(),
		Hosts:             hosts,
	}, nil
}

// VerifyPublicCertificateIssuedByPEM proves leaf is signed by ca. Both inputs
// must contain exactly one public certificate and no private material.
func VerifyPublicCertificateIssuedByPEM(leafPEM, caPEM []byte) error {
	leaf, err := parseSingleCertificatePEM(leafPEM)
	if err != nil {
		return fmt.Errorf("crypto: parse leaf certificate: %w", err)
	}
	ca, err := parseSingleCertificatePEM(caPEM)
	if err != nil {
		return fmt.Errorf("crypto: parse CA certificate: %w", err)
	}
	if !ca.IsCA {
		return errors.New("crypto: issuer certificate is not a CA")
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("crypto: verify certificate issuer: %w", err)
	}
	return nil
}

func parseSingleCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("crypto: expected exactly one CERTIFICATE PEM block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse certificate: %w", err)
	}
	return certificate, nil
}
