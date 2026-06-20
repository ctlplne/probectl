// SPDX-License-Identifier: LicenseRef-probectl-TBD

package crypto

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
	"time"
)

func TestCertificatePinPEMHashesFirstCertificateDER(t *testing.T) {
	ca, err := GenerateCA("pin-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := ca.IssueServerCert("control", []string{"control.local"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("server cert PEM did not decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	got, err := CertificatePinPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString(Hash(cert.Raw))
	if got != want {
		t.Fatalf("pin = %s, want %s", got, want)
	}
}

func TestCertificatePinPEMRejectsMissingCertificate(t *testing.T) {
	if _, err := CertificatePinPEM([]byte("not pem")); err == nil {
		t.Fatal("CertificatePinPEM accepted non-PEM input")
	}
}
