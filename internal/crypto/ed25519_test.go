package crypto

import (
	"bytes"
	"testing"
)

func TestEd25519RoundTrip(t *testing.T) {
	priv, pub, err := GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(priv, []byte("PRIVATE KEY")) || !bytes.Contains(pub, []byte("PUBLIC KEY")) {
		t.Fatal("keys must be PEM-encoded")
	}

	data := []byte("probectl license payload")
	sig, err := SignEd25519(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyEd25519(pub, data, sig)
	if err != nil || !ok {
		t.Fatalf("valid signature must verify: ok=%v err=%v", ok, err)
	}

	// Tampered payload fails.
	if ok, _ := VerifyEd25519(pub, []byte("tampered"), sig); ok {
		t.Fatal("tampered payload must not verify")
	}
	// Tampered signature fails.
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xff
	if ok, _ := VerifyEd25519(pub, data, bad); ok {
		t.Fatal("tampered signature must not verify")
	}
	// Wrong key fails.
	_, otherPub, err := GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyEd25519(otherPub, data, sig); ok {
		t.Fatal("wrong key must not verify")
	}
}

func TestEd25519ParseRejectsGarbage(t *testing.T) {
	if _, err := ParseEd25519PrivatePEM([]byte("not pem")); err == nil {
		t.Fatal("garbage private key must error")
	}
	if _, err := ParseEd25519PublicPEM([]byte("not pem")); err == nil {
		t.Fatal("garbage public key must error")
	}
	// An RSA key is not an Ed25519 key.
	rsaPEM, err := GenerateRSAKeyPEM(2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEd25519PrivatePEM(rsaPEM); err == nil {
		t.Fatal("rsa key must be rejected as ed25519")
	}
}
