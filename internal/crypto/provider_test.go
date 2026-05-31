package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := Random(KeySize)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("tenant secret value")
	aad := []byte("column:agents.secret")

	ct, err := Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Error("ciphertext leaks plaintext")
	}
	got, err := Decrypt(key, ct, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip = %q, want %q", got, plaintext)
	}
}

func TestDecryptFailsOnWrongKeyOrAAD(t *testing.T) {
	key, _ := Random(KeySize)
	other, _ := Random(KeySize)
	ct, _ := Encrypt(key, []byte("secret"), []byte("aad"))

	if _, err := Decrypt(other, ct, []byte("aad")); err == nil {
		t.Error("decrypt with the wrong key should fail")
	}
	if _, err := Decrypt(key, ct, []byte("different-aad")); err == nil {
		t.Error("decrypt with the wrong aad should fail")
	}
}

func TestEncryptRejectsBadKeySize(t *testing.T) {
	if _, err := Encrypt([]byte("short"), []byte("x"), nil); err == nil {
		t.Error("a non-32-byte key should be rejected")
	}
}

func TestSignVerify(t *testing.T) {
	key, _ := Random(32)
	data := []byte("audit payload")
	mac := Sign(key, data)

	if !Verify(key, data, mac) {
		t.Error("a valid MAC should verify")
	}
	if Verify(key, []byte("tampered"), mac) {
		t.Error("tampered data must not verify")
	}
	other, _ := Random(32)
	if Verify(other, data, mac) {
		t.Error("a MAC under a different key must not verify")
	}
}

func TestRandom(t *testing.T) {
	a, err := Random(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 16 {
		t.Errorf("len = %d, want 16", len(a))
	}
	if b, _ := Random(16); bytes.Equal(a, b) {
		t.Error("two random reads should differ")
	}
}
