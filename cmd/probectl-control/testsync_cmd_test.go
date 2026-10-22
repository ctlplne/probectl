// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
)

// G9: `probectl-control testsync public-key` prints exactly the public half of
// the configured signing key (what enrollment hands agents), and never mints a
// key that does not exist yet.
func TestTestSyncPublicKeyCommand(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "testsync.key")
	_, pub, _, err := crypto.LoadOrGenerateEd25519KeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	env := func(k string) string {
		if k == "PROBECTL_TESTSYNC_SIGNING_KEY_FILE" {
			return keyFile
		}
		return ""
	}
	var out bytes.Buffer
	if err := runTestSync([]string{"public-key"}, env, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), pub) {
		t.Fatalf("printed %q, want the public half of the configured key", out.String())
	}

	missing := filepath.Join(dir, "absent.key")
	if err := runTestSync([]string{"public-key", "-key-file", missing}, env, &out); err == nil {
		t.Fatal("a missing key must be an error")
	}
	if _, err := os.Stat(missing); err == nil {
		t.Fatal("public-key must never create a signing key")
	}
	if err := runTestSync(nil, env, &out); err == nil {
		t.Fatal("no subcommand must print usage as an error")
	}
	if err := runTestSync([]string{"public-key"}, func(string) string { return "" }, &out); err == nil {
		t.Fatal("no key file configured must be an error")
	}
}

// G9 HA: the inline, secret-injected key (Helm) is the one serve uses, so the
// command prints its public half — and serve's resolver agrees, preferring it
// over a key file exactly as the command does.
func TestTestSyncPublicKeyCommandInlineKey(t *testing.T) {
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	otherFile := filepath.Join(dir, "other.key")
	if _, _, _, err := crypto.LoadOrGenerateEd25519KeyFile(otherFile); err != nil {
		t.Fatal(err)
	}
	inline := base64.StdEncoding.EncodeToString(priv)
	env := func(k string) string {
		switch k {
		case "PROBECTL_TESTSYNC_SIGNING_KEY":
			return inline
		case "PROBECTL_TESTSYNC_SIGNING_KEY_FILE":
			return otherFile
		}
		return ""
	}
	var out bytes.Buffer
	if err := runTestSync([]string{"public-key"}, env, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), pub) {
		t.Fatal("public-key must print the inline key's public half when PROBECTL_TESTSYNC_SIGNING_KEY is set")
	}

	_, gotPub, generated, from, err := loadTestSyncSigningKey(&config.Config{TestSyncSigningKey: inline, TestSyncSigningKeyFile: otherFile})
	if err != nil || generated || !bytes.Equal(gotPub, pub) || from != "PROBECTL_TESTSYNC_SIGNING_KEY" {
		t.Fatalf("serve resolver = pub match %v, generated %v, from %q, err %v; want the inline key", bytes.Equal(gotPub, pub), generated, from, err)
	}
	if _, _, _, _, err := loadTestSyncSigningKey(&config.Config{TestSyncSigningKey: "not base64!"}); err == nil {
		t.Fatal("a malformed inline key must refuse to start, not fall back to a file")
	}
	if priv, _, _, _, err := loadTestSyncSigningKey(&config.Config{}); err != nil || priv != nil {
		t.Fatal("no key configured must leave central test distribution off")
	}
}
