// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otlp

import (
	"context"
	"testing"
	"time"
)

func TestTokenAuthenticatorBasics(t *testing.T) {
	a := NewTokenAuthenticator(map[string]string{"sekret": "tenant-a", "": "x", "y": ""})
	if got, err := a.Authenticate(context.Background(), "sekret"); err != nil || got != "tenant-a" {
		t.Fatalf("valid token = %q, %v", got, err)
	}
	if _, err := a.Authenticate(context.Background(), "wrong"); err != ErrUnauthenticated {
		t.Fatalf("wrong token err = %v, want ErrUnauthenticated", err)
	}
	if _, err := a.Authenticate(context.Background(), ""); err != ErrUnauthenticated {
		t.Fatalf("empty token err = %v", err)
	}
	// empty key/value pairs are dropped, so only one active token exists.
	if a.ActiveTokens() != 1 {
		t.Fatalf("active = %d, want 1", a.ActiveTokens())
	}
}

func TestTokenAuthenticatorStoresNoPlaintext(t *testing.T) {
	a := NewTokenAuthenticator(map[string]string{"super-secret-token": "t"})
	for _, e := range a.entries {
		if string(e.hash) == "super-secret-token" || len(e.hash) != 32 {
			t.Fatalf("entry must store a 32-byte hash, not the plaintext: %v", e.hash)
		}
	}
}

func TestTokenRotation(t *testing.T) {
	a := NewTokenAuthenticator(map[string]string{"old": "t1"})
	// Add the new token: BOTH are valid during the migration window (U-077).
	a.Add("new", "t1", time.Time{})
	for _, tok := range []string{"old", "new"} {
		if got, err := a.Authenticate(context.Background(), tok); err != nil || got != "t1" {
			t.Fatalf("during rotation %q = %q,%v", tok, got, err)
		}
	}
	if a.ActiveTokens() != 2 {
		t.Fatalf("active during rotation = %d, want 2", a.ActiveTokens())
	}
	// Revoke the old token: it stops authenticating immediately; the new one
	// keeps working.
	if !a.Revoke("old") {
		t.Fatal("Revoke(old) reported no match")
	}
	if _, err := a.Authenticate(context.Background(), "old"); err != ErrUnauthenticated {
		t.Fatalf("revoked token still authenticates")
	}
	if got, _ := a.Authenticate(context.Background(), "new"); got != "t1" {
		t.Fatalf("post-rotation token broke: %q", got)
	}
	if a.Revoke("never-existed") {
		t.Fatal("revoking an unknown token must report no match")
	}
}

func TestTokenExpiry(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	a := NewTokenAuthenticator(nil)
	a.now = func() time.Time { return now }
	a.Add("temp", "t2", now.Add(time.Hour))

	if got, err := a.Authenticate(context.Background(), "temp"); err != nil || got != "t2" {
		t.Fatalf("unexpired = %q,%v", got, err)
	}
	now = now.Add(2 * time.Hour) // past expiry
	if _, err := a.Authenticate(context.Background(), "temp"); err != ErrUnauthenticated {
		t.Fatal("expired token must fail closed")
	}
	if a.ActiveTokens() != 0 {
		t.Fatalf("expired token still counted active: %d", a.ActiveTokens())
	}
}
