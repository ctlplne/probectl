// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

// TestDecryptOpensLegacyCallerNonceCiphertext proves the RTT-05 switch to
// NewGCMWithRandomNonce did NOT change the wire format: a ciphertext sealed the
// OLD way — a regular cipher.NewGCM with a caller-chosen 12-byte nonce prepended
// via Seal(nonce, nonce, ...) — must still open under the current Decrypt, so
// DEKs and envelope columns written by earlier builds stay decryptable. The
// legacy seal is built with a regular GCM directly (not the package's newGCM,
// which is now random-nonce) to faithfully reproduce the on-disk bytes an older
// binary produced.
func TestDecryptOpensLegacyCallerNonceCiphertext(t *testing.T) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	pt := []byte("tenant-scoped envelope plaintext")
	aad := []byte("probectl.aad.v1")

	// --- Reproduce the OLD encrypt path exactly (regular GCM, caller nonce). ---
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	reg, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	nonce := make([]byte, reg.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	legacy := reg.Seal(nonce, nonce, pt, aad) // old wire layout: nonce || ct||tag

	got, err := Decrypt(key, legacy, aad)
	if err != nil {
		t.Fatalf("current Decrypt failed to open legacy caller-nonce ciphertext: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatalf("legacy round-trip mismatch: got %q want %q", got, pt)
	}

	// --- And the current Encrypt->Decrypt round-trips (forward direction). ---
	ctNew, err := Encrypt(key, pt, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got2, err := Decrypt(key, ctNew, aad)
	if err != nil || string(got2) != string(pt) {
		t.Fatalf("new round-trip failed: got %q err %v", got2, err)
	}

	// Current ciphertext is also openable by the OLD manual decrypt (12-byte
	// nonce prefix), confirming the layout is unchanged in both directions.
	ns := reg.NonceSize()
	if len(ctNew) < ns {
		t.Fatalf("new ciphertext shorter than a nonce (%d bytes)", len(ctNew))
	}
	oldOpened, err := reg.Open(nil, ctNew[:ns], ctNew[ns:], aad)
	if err != nil || string(oldOpened) != string(pt) {
		t.Fatalf("legacy decrypt of new ciphertext failed: got %q err %v", oldOpened, err)
	}
}
