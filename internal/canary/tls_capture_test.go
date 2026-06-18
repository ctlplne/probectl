// SPDX-License-Identifier: LicenseRef-probectl-TBD

package canary

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// The S13 capture is extended for S27: attachTLS records the leaf cert DER + the
// chain-verification result so the TLS-posture observer reuses captured data
// (never re-handshakes).
func TestAttachTLSCapturesLeafAndVerified(t *testing.T) {
	leaf, _, err := crypto.GenerateTestCert(crypto.TestCertOptions{CommonName: "x.example", DNSNames: []string{"x.example"}})
	if err != nil {
		t.Fatal(err)
	}
	cs := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{leaf},
	}
	res := Result{Attributes: map[string]string{}, Metrics: map[string]float64{}}
	verified := true
	attachTLS(&res, cs, &verified, time.Now())

	if res.Attributes["probectl.tls.server.verified"] != "true" {
		t.Errorf("probectl.tls.server.verified = %q, want true", res.Attributes["probectl.tls.server.verified"])
	}
	raw, err := base64.StdEncoding.DecodeString(res.Attributes["probectl.tls.server.cert"])
	if err != nil {
		t.Fatalf("leaf cert not captured as base64 DER: %v", err)
	}
	parsed, err := x509.ParseCertificate(raw)
	if err != nil || parsed.Subject.CommonName != "x.example" {
		t.Errorf("captured leaf = %v (err %v)", parsed, err)
	}
}
