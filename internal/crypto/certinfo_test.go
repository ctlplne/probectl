package crypto

import "testing"

func TestCertKeyInfo(t *testing.T) {
	rsaCert, _, err := GenerateTestCert(TestCertOptions{CommonName: "rsa.test", RSABits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	if kt, kb := CertKeyInfo(rsaCert); kt != "RSA" || kb != 2048 {
		t.Errorf("RSA key info = %s/%d, want RSA/2048", kt, kb)
	}

	ecCert, _, err := GenerateTestCert(TestCertOptions{CommonName: "ec.test"})
	if err != nil {
		t.Fatal(err)
	}
	if kt, kb := CertKeyInfo(ecCert); kt != "ECDSA" || kb != 256 {
		t.Errorf("ECDSA key info = %s/%d, want ECDSA/256", kt, kb)
	}
}

func TestGenerateTestCertSelfSigned(t *testing.T) {
	ss, _, err := GenerateTestCert(TestCertOptions{CommonName: "self.test", SelfSigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if ss.Subject.String() != ss.Issuer.String() {
		t.Error("self-signed cert subject should equal issuer")
	}
	leaf, _, err := GenerateTestCert(TestCertOptions{CommonName: "leaf.test"})
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.String() == leaf.Issuer.String() {
		t.Error("CA-issued cert subject should differ from issuer")
	}
}
