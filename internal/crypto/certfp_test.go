package crypto

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestCertSHA1(t *testing.T) {
	c, _, err := GenerateTestCert(TestCertOptions{CommonName: "fp.example", DNSNames: []string{"fp.example"}, NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	fp := CertSHA1(c)
	if len(fp) != 40 {
		t.Fatalf("sha1 hex length = %d (%q), want 40", len(fp), fp)
	}
	if CertSHA1(c) != fp {
		t.Error("CertSHA1 is not deterministic")
	}
	for _, r := range fp {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			// lowercase hex digit — ok
		default:
			t.Fatalf("non-lowercase-hex rune %q in %s", r, fp)
		}
	}
	// nil / empty-DER are safe (return empty, never panic)
	if CertSHA1(nil) != "" {
		t.Error("CertSHA1(nil) should be empty")
	}
	if CertSHA1(&x509.Certificate{}) != "" {
		t.Error("CertSHA1 of an empty-raw cert should be empty")
	}
}
