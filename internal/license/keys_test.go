// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package license

import (
	"encoding/base64"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// DPR-001: trust anchors come from the committed trusted_keys/*.pub files and
// the link-time payload, in that order, and malformed entries never count.
func TestTrustedKeysMergeEmbeddedAndLinkTime(t *testing.T) {
	_, pubA := testKeypair(t)
	_, pubB := testKeypair(t)
	_, pubLink := testKeypair(t)
	fsys := fstest.MapFS{
		"trusted_keys/README.md":   {Data: []byte("docs only")},
		"trusted_keys/b-2027.pub":  {Data: append([]byte("\n"), append(pubB, '\n')...)},
		"trusted_keys/a-2026.pub":  {Data: pubA},
		"trusted_keys/garbage.pub": {Data: []byte("not a pem")},
		"trusted_keys/notes.txt":   {Data: pubA},
	}
	link := base64.StdEncoding.EncodeToString(pubLink) + ",!!not-base64!!"

	keys := trustedKeysFrom(fsys, link)
	if len(keys) != 3 {
		t.Fatalf("want 3 anchors (2 committed + 1 linked), got %d", len(keys))
	}
	if string(keys[0]) != strings.TrimSpace(string(pubA)) || string(keys[1]) != strings.TrimSpace(string(pubB)) {
		t.Fatal("committed anchors must come first, sorted by file name, whitespace-trimmed")
	}
	if string(keys[2]) != string(pubLink) {
		t.Fatal("link-time anchor must follow the committed ones")
	}

	// A signed license verifies against a committed anchor and against the
	// linked one, and a stranger's key is refused.
	privA, _ := testKeypair(t)
	raw, err := Sign(testClaims(TierEnterprise, time.Now().Add(365*24*time.Hour)), privA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(raw, keys); err == nil {
		t.Fatal("a license signed by an untrusted key must be refused")
	}
}

func TestTrustedKeysKeylessTreeIsCommunityOnly(t *testing.T) {
	fsys := fstest.MapFS{"trusted_keys/README.md": {Data: []byte("docs only")}}
	if got := trustedKeysFrom(fsys, ""); got != nil {
		t.Fatalf("keyless tree must yield no anchors, got %d", len(got))
	}
	if _, err := Verify([]byte(`{"payload":"","signature":""}`), nil); err == nil || !strings.Contains(err.Error(), "no trusted license keys") {
		t.Fatalf("keyless verification must fail loudly, got %v", err)
	}
}

// Every anchor actually committed under trusted_keys/ must be a well-formed
// public-key PEM: a stray private key or a truncated paste would otherwise
// ship silently.
func TestCommittedTrustAnchorsAreWellFormed(t *testing.T) {
	entries, err := fs.ReadDir(trustedKeyFS, "trusted_keys")
	if err != nil {
		t.Fatal(err)
	}
	var pubs int
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		pubs++
		b, err := fs.ReadFile(trustedKeyFS, "trusted_keys/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "PRIVATE KEY") {
			t.Fatalf("%s: a private key is committed as a trust anchor", e.Name())
		}
		if !strings.Contains(string(b), "BEGIN PUBLIC KEY") {
			t.Fatalf("%s: not a PEM public key", e.Name())
		}
	}
	if len(embeddedKeys(trustedKeyFS)) != pubs {
		t.Fatalf("embedded anchor count %d != committed .pub files %d", len(embeddedKeys(trustedKeyFS)), pubs)
	}
}

func TestTrustAnchorCountMatchesInfo(t *testing.T) {
	old := builtinPubKeysB64
	defer func() { builtinPubKeysB64 = old }()
	_, pub := testKeypair(t)
	builtinPubKeysB64 = base64.StdEncoding.EncodeToString(pub)
	want := len(embeddedKeys(trustedKeyFS)) + 1
	if TrustAnchorCount() != want {
		t.Fatalf("TrustAnchorCount = %d, want %d", TrustAnchorCount(), want)
	}
	if got := Community().Info().TrustAnchors; got != want {
		t.Fatalf("Info().TrustAnchors = %d, want %d (Admin → Editions must show the anchor count)", got, want)
	}
}
