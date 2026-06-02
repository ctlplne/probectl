package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

// TestCertOptions configures a certificate built by GenerateTestCert.
type TestCertOptions struct {
	CommonName string
	DNSNames   []string
	NotBefore  time.Time // default: 1h ago
	NotAfter   time.Time // default: 1 year out
	RSABits    int       // >0 → RSA of that size; 0 → ECDSA P-256
	SelfSigned bool      // subject == issuer
}

// GenerateTestCert creates a certificate (returning the parsed cert + its DER) for
// tests — expired/expiring/self-signed/weak-key cases for the S27 TLS-posture
// observer. It lives in internal/crypto so test code elsewhere never imports
// crypto/rsa|ecdsa|rand directly (the FIPS import guard).
func GenerateTestCert(o TestCertOptions) (*x509.Certificate, []byte, error) {
	if o.NotBefore.IsZero() {
		o.NotBefore = time.Now().Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	}

	var pub, priv any
	if o.RSABits > 0 {
		k, err := rsa.GenerateKey(rand.Reader, o.RSABits)
		if err != nil {
			return nil, nil, err
		}
		pub, priv = &k.PublicKey, k
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub, priv = &k.PublicKey, k
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: o.CommonName, Organization: []string{"netctl-test"}},
		NotBefore:    o.NotBefore,
		NotAfter:     o.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     o.DNSNames,
	}

	parent, parentKey := tmpl, priv
	if !o.SelfSigned {
		ik, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		iserial, err := randomSerial()
		if err != nil {
			return nil, nil, err
		}
		parent = &x509.Certificate{
			SerialNumber:          iserial,
			Subject:               pkix.Name{CommonName: "netctl Test CA", Organization: []string{"netctl-test-ca"}},
			NotBefore:             o.NotBefore,
			NotAfter:              o.NotAfter,
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		parentKey = ik
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, der, nil
}
