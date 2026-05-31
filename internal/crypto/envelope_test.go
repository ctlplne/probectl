package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
)

func newTestEnvelope(t *testing.T) *Envelope {
	t.Helper()
	kek, err := Random(KeySize)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := NewStaticKeyProvider("dev-1", kek)
	if err != nil {
		t.Fatal(err)
	}
	return NewEnvelope(kp)
}

func TestEnvelopeRoundTrip(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvelope(t)
	plaintext := []byte("super secret api token")
	aad := []byte("tenant:abc/agents:secret")

	sealed, err := env.Seal(ctx, plaintext, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if sealed.KeyID != "dev-1" {
		t.Errorf("keyID = %q, want dev-1", sealed.KeyID)
	}
	if bytes.Contains(sealed.Ciphertext, plaintext) {
		t.Error("ciphertext leaks plaintext")
	}
	got, err := env.Open(ctx, sealed, aad)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip = %q, want %q", got, plaintext)
	}
}

func TestEnvelopeAADMismatchFails(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvelope(t)
	sealed, _ := env.Seal(ctx, []byte("x"), []byte("aad-1"))
	if _, err := env.Open(ctx, sealed, []byte("aad-2")); err == nil {
		t.Error("opening with a different aad must fail")
	}
}

func TestSealedEncodeDecode(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvelope(t)
	sealed, _ := env.Seal(ctx, []byte("payload"), []byte("aad"))

	encoded, err := sealed.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	back, err := DecodeSealed(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if back.KeyID != sealed.KeyID ||
		!bytes.Equal(back.WrappedDEK, sealed.WrappedDEK) ||
		!bytes.Equal(back.Ciphertext, sealed.Ciphertext) {
		t.Fatalf("decode mismatch:\n got  %+v\n want %+v", back, sealed)
	}
	got, err := env.Open(ctx, back, []byte("aad"))
	if err != nil || string(got) != "payload" {
		t.Errorf("decoded value did not open: %q / %v", got, err)
	}
}

func TestNewStaticKeyProviderFromBase64(t *testing.T) {
	kek, _ := Random(KeySize)
	if _, err := NewStaticKeyProviderFromBase64("k1", base64.StdEncoding.EncodeToString(kek)); err != nil {
		t.Fatalf("valid kek: %v", err)
	}
	if _, err := NewStaticKeyProviderFromBase64("k1", "not base64 !!"); err == nil {
		t.Error("invalid base64 should fail")
	}
	if _, err := NewStaticKeyProviderFromBase64("k1", base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("a short KEK should fail")
	}
}
