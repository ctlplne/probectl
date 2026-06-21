// SPDX-License-Identifier: LicenseRef-probectl-TBD

package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestSignRSAPSSRoundTrip is the KEYS-001 acceptance test: proves SignRSAPSS /
// VerifyRSAPSS exist (PSS path), that a valid signature verifies, and that
// tampered data / tampered signatures are rejected. Run:
//
//	go test ./internal/crypto/... -run TestSignRSAPSS
func TestSignRSAPSSRoundTrip(t *testing.T) {
	privPEM, err := GenerateRSAKeyPEM(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPEM: %v", err)
	}

	// Derive the matching public key PEM.
	block, _ := pem.Decode(privPEM)
	if block == nil {
		t.Fatal("no PEM block")
	}
	pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	rsaKey, ok := pk.(interface {
		Public() interface{ Equal(interface{}) bool }
	})
	_ = rsaKey
	_ = ok

	// Use the crypto helper so we stay inside internal/crypto.
	privKey, err := parseRSAPrivatePEM(privPEM)
	if err != nil {
		t.Fatalf("parseRSAPrivatePEM: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	data := []byte("probectl KEYS-001 PSS test payload")

	// Sign with PSS.
	sig, err := SignRSAPSS(privPEM, data)
	if err != nil {
		t.Fatalf("SignRSAPSS: %v", err)
	}

	// Valid signature must verify.
	if err := VerifyRSAPSS(pubPEM, data, sig); err != nil {
		t.Fatalf("VerifyRSAPSS valid: %v", err)
	}

	// Tampered data must fail.
	if err := VerifyRSAPSS(pubPEM, []byte("tampered"), sig); err == nil {
		t.Fatal("VerifyRSAPSS should reject tampered data")
	}

	// Tampered signature must fail.
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xff
	if err := VerifyRSAPSS(pubPEM, data, bad); err == nil {
		t.Fatal("VerifyRSAPSS should reject tampered signature")
	}

	// A PKCS#1 v1.5 signature must NOT verify as PSS (proves they are distinct
	// pad modes; confirms PSS is what's being tested, not just SHA-256 digest).
	v15sig, err := SignRS256(privPEM, data)
	if err != nil {
		t.Fatalf("SignRS256: %v", err)
	}
	if err := VerifyRSAPSS(pubPEM, data, v15sig); err == nil {
		t.Fatal("VerifyRSAPSS must reject a PKCS#1 v1.5 signature (padding mismatch)")
	}
}

// TestSignRSAPSSIsNonDeterministic checks that PSS produces different
// signatures on each call (salt randomization — distinguishing it from v1.5).
func TestSignRSAPSSIsNonDeterministic(t *testing.T) {
	privPEM, err := GenerateRSAKeyPEM(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPEM: %v", err)
	}
	data := []byte("same payload")
	sig1, err := SignRSAPSS(privPEM, data)
	if err != nil {
		t.Fatalf("sign1: %v", err)
	}
	sig2, err := SignRSAPSS(privPEM, data)
	if err != nil {
		t.Fatalf("sign2: %v", err)
	}
	if string(sig1) == string(sig2) {
		t.Fatal("PSS signatures must be non-deterministic (probabilistic salt)")
	}
}
