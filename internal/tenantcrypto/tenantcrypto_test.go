// SPDX-License-Identifier: LicenseRef-probectl-TBD

package tenantcrypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func testSealer(t *testing.T, keyID string) *EnvelopeSealer {
	t.Helper()
	s, err := NewEnvelopeSealer(keyID, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testKeyringSealer(t *testing.T, keyID string, keyByte byte, openerKeys map[string]string) *EnvelopeSealer {
	t.Helper()
	s, err := NewEnvelopeKeyringSealer(keyID, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{keyByte}, 32)), openerKeys)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPassthroughWithoutPrimary(t *testing.T) {
	defer Reset()
	Reset()
	ctx := context.Background()
	stored, err := Seal(ctx, "tnA", []byte("plain"), nil)
	if err != nil || stored != "plain" {
		t.Fatalf("keyless seal: %q %v", stored, err)
	}
	p, err := Open(ctx, "tnA", "plain", nil)
	if err != nil || string(p) != "plain" {
		t.Fatalf("keyless open: %q %v", p, err)
	}
	// Plaintext that merely contains a colon is NOT mistaken for a scheme.
	p, err = Open(ctx, "tnA", "user:pass", nil)
	if err != nil || string(p) != "user:pass" {
		t.Fatalf("colon plaintext: %q %v", p, err)
	}
}

func TestDV1RoundTripAndTenantBinding(t *testing.T) {
	defer Reset()
	Reset()
	SetPrimary(testSealer(t, "dep"))
	ctx := context.Background()
	aad := []byte("alert-channel-secret")

	stored, err := Seal(ctx, "tnA", []byte("secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, "dv1:dep:") {
		t.Fatalf("format: %s", stored)
	}
	p, err := Open(ctx, "tnA", stored, aad)
	if err != nil || string(p) != "secret" {
		t.Fatalf("round-trip: %q %v", p, err)
	}
	// The AAD binds the tenant: the same blob refuses to open as another
	// tenant (cross-tenant replay defense even under ONE deployment key).
	if _, err := Open(ctx, "tnB", stored, aad); err == nil {
		t.Fatal("dv1 must not open under another tenant")
	}
	// And binds the caller context.
	if _, err := Open(ctx, "tnA", stored, []byte("other-context")); err == nil {
		t.Fatal("dv1 must not open under a different aad")
	}
}

func TestFailSafeUnknownScheme(t *testing.T) {
	defer Reset()
	Reset()
	ctx := context.Background()
	// A KNOWN minted scheme with no registered sealer must refuse to pass
	// through as plaintext — the fail-safe rule.
	for _, stored := range []string{"dv1:dep:abc:def", "tk1:3:abc"} {
		_, err := Open(ctx, "tnA", stored, nil)
		var unknown ErrUnknownScheme
		if !errors.As(err, &unknown) {
			t.Fatalf("sealed value without its sealer must fail safe: %q -> %v", stored, err)
		}
	}
	// Unminted prefixes remain legacy plaintext (e.g. "https://...").
	p, err := Open(ctx, "tnA", "https://hook.example/x", nil)
	if err != nil || string(p) != "https://hook.example/x" {
		t.Fatalf("url plaintext: %q %v", p, err)
	}
}

func TestSchemeHelpersAndAADBinding(t *testing.T) {
	defer Reset()
	Reset()

	if got := (ErrUnknownScheme{Scheme: "tk1"}).Error(); !strings.Contains(got, "tk1") || !strings.Contains(got, "failing safe") {
		t.Fatalf("unknown-scheme error should name the scheme and fail-safe posture: %q", got)
	}
	if HasScheme("dv1:dep:abc:def") {
		t.Fatal("unregistered dv1 must not report as sealed by an available scheme")
	}

	SetPrimary(testSealer(t, "dep"))
	if !HasScheme("dv1:dep:abc:def") {
		t.Fatal("registered dv1 value should report as sealed")
	}
	for _, stored := range []string{"plain", "user:pass", "tk1:1:abc"} {
		if HasScheme(stored) {
			t.Fatalf("%q must not report as sealed by an available scheme", stored)
		}
	}

	got := BindAAD("tenant-a", []byte("alert"))
	if string(got) != "tenant:tenant-a:alert" {
		t.Fatalf("BindAAD = %q, want tenant-bound prefix", got)
	}
}

func TestOpenerChainAcrossPrimaryChange(t *testing.T) {
	defer Reset()
	Reset()
	ctx := context.Background()
	dep := testSealer(t, "dep")
	SetPrimary(dep)
	legacy, err := Seal(ctx, "tnA", []byte("old"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Clearing the primary (keyless restart) keeps registered openers: the
	// legacy value still opens, new writes pass through.
	SetPrimary(nil)
	AddOpener(dep)
	if p, err := Open(ctx, "tnA", legacy, nil); err != nil || string(p) != "old" {
		t.Fatalf("legacy after primary change: %q %v", p, err)
	}
	if stored, err := Seal(ctx, "tnA", []byte("new"), nil); err != nil || stored != "new" {
		t.Fatalf("passthrough after clear: %q %v", stored, err)
	}
}

func TestDV1KeyringOpensOldAndNewAfterRotation(t *testing.T) {
	defer Reset()
	Reset()
	ctx := context.Background()
	aad := []byte("alert-channel-secret")

	SetPrimary(testKeyringSealer(t, "old", 1, nil))
	oldStored, err := Seal(ctx, "tnA", []byte("old secret"), aad)
	if err != nil {
		t.Fatal(err)
	}

	oldB64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	SetPrimary(testKeyringSealer(t, "new", 2, map[string]string{"old": oldB64}))
	newStored, err := Seal(ctx, "tnA", []byte("new secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(newStored, "dv1:new:") {
		t.Fatalf("new format: %s", newStored)
	}
	for stored, want := range map[string]string{oldStored: "old secret", newStored: "new secret"} {
		got, err := Open(ctx, "tnA", stored, aad)
		if err != nil || string(got) != want {
			t.Fatalf("open rotated value %q: %q %v", want, got, err)
		}
	}
	if _, err := Open(ctx, "tnB", oldStored, aad); err == nil {
		t.Fatal("old dv1 value must still be tenant-bound after keyring rotation")
	}
}

func TestDeploymentEnvelopeRewrapMovesOldKeyIDToActive(t *testing.T) {
	defer Reset()
	Reset()
	ctx := context.Background()
	aad := []byte("alert-channel-secret")

	SetPrimary(testKeyringSealer(t, "old", 1, nil))
	oldStored, err := Seal(ctx, "tnA", []byte("old secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if keyID, ok := DeploymentEnvelopeKeyID(oldStored); !ok || keyID != "old" {
		t.Fatalf("old key id = %q/%v, want old/true", keyID, ok)
	}

	oldB64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	SetPrimary(testKeyringSealer(t, "new", 2, map[string]string{"old": oldB64}))
	rewrapped, err := RewrapDeploymentEnvelope(ctx, "tnA", oldStored, aad)
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if keyID, ok := DeploymentEnvelopeKeyID(rewrapped); !ok || keyID != "new" {
		t.Fatalf("rewrapped key id = %q/%v, want new/true", keyID, ok)
	}

	Reset()
	SetPrimary(testKeyringSealer(t, "new", 2, nil))
	got, err := Open(ctx, "tnA", rewrapped, aad)
	if err != nil || string(got) != "old secret" {
		t.Fatalf("rewrapped value must open after old opener removal: %q %v", got, err)
	}
	if _, err := Open(ctx, "tnA", oldStored, aad); err == nil {
		t.Fatal("old ciphertext must not open after old opener removal")
	}
}

func TestDeploymentEnvelopeRewrapRejectsNonDV1AndKeylessOutput(t *testing.T) {
	defer Reset()
	Reset()
	ctx := context.Background()

	if _, err := RewrapDeploymentEnvelope(ctx, "tnA", "plain", nil); err == nil || !strings.Contains(err.Error(), "not a dv1") {
		t.Fatalf("non-dv1 rewrap must fail closed, got %v", err)
	}

	dep := testSealer(t, "old")
	SetPrimary(dep)
	oldStored, err := Seal(ctx, "tnA", []byte("old secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	SetPrimary(nil) // opener remains, but new seals would be plaintext.
	AddOpener(dep)
	if _, err := RewrapDeploymentEnvelope(ctx, "tnA", oldStored, nil); err == nil || !strings.Contains(err.Error(), "did not produce a dv1") {
		t.Fatalf("rewrap must refuse keyless/plaintext output, got %v", err)
	}
}

func TestDestroyKeysWithoutDestroyer(t *testing.T) {
	defer Reset()
	Reset()
	SetPrimary(testSealer(t, "dep")) // EnvelopeSealer is not a Destroyer
	n, supported, err := DestroyKeys(context.Background(), "tnA")
	if err != nil || supported || n != 0 {
		t.Fatalf("deployment sealer must report unsupported: n=%d supported=%v err=%v", n, supported, err)
	}
}

type destroyerSealer struct {
	*EnvelopeSealer
	n   int
	err error
}

func (s destroyerSealer) DestroyKeys(context.Context, string) (int, error) {
	return s.n, s.err
}

func TestDestroyKeysWithDestroyer(t *testing.T) {
	defer Reset()
	Reset()
	wantErr := errors.New("kms offline")
	SetPrimary(destroyerSealer{EnvelopeSealer: testSealer(t, "dep"), n: 2, err: wantErr})
	n, supported, err := DestroyKeys(context.Background(), "tnA")
	if !supported || n != 2 || !errors.Is(err, wantErr) {
		t.Fatalf("destroyer result = n=%d supported=%v err=%v, want n=2 supported err", n, supported, err)
	}
}

func TestMalformedDV1(t *testing.T) {
	defer Reset()
	Reset()
	SetPrimary(testSealer(t, "dep"))
	ctx := context.Background()
	for _, bad := range []string{"dv1:onlykey", "dv1:k:!!!:abc", "dv1:k:abc:!!!"} {
		if _, err := Open(ctx, "tnA", bad, nil); err == nil {
			t.Fatalf("malformed dv1 must error: %q", bad)
		}
	}
}
