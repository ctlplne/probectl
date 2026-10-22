// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

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
