// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/license"
)

// DPR-005: the vendor CLI can re-issue a license with its original issue
// date, or mint an already-expired file for grace/read-only drills, and it
// refuses an inverted window at signing time instead of handing out a file
// that fails to load.
func TestSignIssuedFlagBackdatesTheLicense(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k.key"), filepath.Join(dir, "k.pub")
	if err := genKey([]string{"-out-priv", priv, "-out-pub", pub}); err != nil {
		t.Fatal(err)
	}
	pubPEM, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "backdated.json")
	if err := sign([]string{"-key", priv, "-customer", "Drill", "-tier", "msp", "-issued", "2026-01-15", "-expires", "2026-02-15", "-out", out}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	c, err := license.Verify(raw, [][]byte{pubPEM})
	if err != nil {
		t.Fatalf("backdated license must verify (expiry is a state, not a parse error): %v", err)
	}
	if !c.IssuedAt.Equal(time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("issued_at = %s, want 2026-01-15T00:00:00Z", c.IssuedAt)
	}
	if !c.ExpiresAt.Equal(time.Date(2026, 2, 15, 23, 59, 59, 0, time.UTC)) {
		t.Fatalf("expires_at = %s, want 2026-02-15T23:59:59Z", c.ExpiresAt)
	}

	inverted := filepath.Join(dir, "inverted.json")
	if err := sign([]string{"-key", priv, "-customer", "Drill", "-tier", "msp", "-issued", "2026-03-01", "-expires", "2026-02-15", "-out", inverted}); err == nil {
		t.Fatal("an expiry before the issue date must be refused at signing time")
	}
	if _, err := os.Stat(inverted); err == nil {
		t.Fatal("a refused license must not be written")
	}

	// Without -issued the file is issued now, as before.
	now := filepath.Join(dir, "now.json")
	before := time.Now().UTC().Truncate(time.Second)
	if err := sign([]string{"-key", priv, "-customer", "Drill", "-tier", "enterprise", "-expires", "2099-01-01", "-out", now}); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(now)
	c, err = license.Verify(raw, [][]byte{pubPEM})
	if err != nil {
		t.Fatal(err)
	}
	if c.IssuedAt.Before(before) || c.IssuedAt.After(time.Now().UTC().Add(time.Minute)) {
		t.Fatalf("default issued_at = %s, want ≈ now", c.IssuedAt)
	}
}
