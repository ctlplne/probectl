// SPDX-License-Identifier: LicenseRef-probectl-TBD

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

func TestEnvelopeKeyringOpensOldAndNewAfterRotation(t *testing.T) {
	ctx := context.Background()
	oldKEK, err := Random(KeySize)
	if err != nil {
		t.Fatal(err)
	}
	newKEK, err := Random(KeySize)
	if err != nil {
		t.Fatal(err)
	}
	oldProvider, err := NewStaticKeyProvider("old", oldKEK)
	if err != nil {
		t.Fatal(err)
	}
	oldEnv := NewEnvelope(oldProvider)
	oldSealed, err := oldEnv.Seal(ctx, []byte("old payload"), []byte("aad"))
	if err != nil {
		t.Fatalf("seal old: %v", err)
	}

	newProvider, err := NewStaticKeyringProvider("new", newKEK, map[string][]byte{"old": oldKEK})
	if err != nil {
		t.Fatal(err)
	}
	newEnv := NewEnvelope(newProvider)
	if got, err := newEnv.Open(ctx, oldSealed, []byte("aad")); err != nil || string(got) != "old payload" {
		t.Fatalf("open old after rotation: %q %v", got, err)
	}
	newSealed, err := newEnv.Seal(ctx, []byte("new payload"), []byte("aad"))
	if err != nil {
		t.Fatalf("seal new: %v", err)
	}
	if newSealed.KeyID != "new" {
		t.Fatalf("new seal key id = %q, want new", newSealed.KeyID)
	}
	if got, err := newEnv.Open(ctx, newSealed, []byte("aad")); err != nil || string(got) != "new payload" {
		t.Fatalf("open new after rotation: %q %v", got, err)
	}

	currentOnly, err := NewStaticKeyProvider("new", newKEK)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEnvelope(currentOnly).Open(ctx, oldSealed, []byte("aad")); err == nil {
		t.Fatal("current-only provider must not open a sealed value for an old key id")
	}
	oldSealed.KeyID = "missing"
	if _, err := newEnv.Open(ctx, oldSealed, []byte("aad")); err == nil {
		t.Fatal("unknown key id must fail closed")
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

func TestNewStaticKeyProviderFromBase64KeyringRejectsBadOpeners(t *testing.T) {
	kek, _ := Random(KeySize)
	b64 := base64.StdEncoding.EncodeToString(kek)
	if _, err := NewStaticKeyProviderFromBase64Keyring("k1", b64, map[string]string{"old": "not base64"}); err == nil {
		t.Fatal("invalid opener base64 must fail")
	}
	if _, err := NewStaticKeyProviderFromBase64Keyring("k1", b64, map[string]string{"old": base64.StdEncoding.EncodeToString([]byte("short"))}); err == nil {
		t.Fatal("short opener KEK must fail")
	}
	if _, err := NewStaticKeyProviderFromBase64Keyring("k1", b64, map[string]string{"k1": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, KeySize))}); err == nil {
		t.Fatal("opener key id must not collide with active key id")
	}
}
