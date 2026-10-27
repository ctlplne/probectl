// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package controlstate_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/controlstate"
	"github.com/ctlplne/probectl/internal/crypto"
)

// The restored startup key must preserve the identity trusted by audit verifiers.
func TestFreshHostRestoreKeepsAuditSigningIdentity(t *testing.T) {
	ctx := context.Background()
	dirA := t.TempDir()
	evidenceA := filepath.Join(dirA, "evidence.pem")
	wormA := filepath.Join(dirA, "worm-signing-ed25519.pem")
	if _, _, _, err := crypto.LoadOrGenerateEd25519KeyFile(evidenceA); err != nil {
		t.Fatal(err)
	}
	_, agentPub, generated, err := audit.ResolveWormSigningKey("", wormA, true)
	if err != nil || !generated {
		t.Fatalf("host A first-boot WORM key: generated=%v err=%v", generated, err)
	}
	keys := staticProvider(t, "file")

	st, err := controlstate.Capture(controlstate.Paths{
		EvidenceSigningKeyFile: evidenceA, WormSigningKeyFile: wormA,
	}, "file", nil)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	var artifact bytes.Buffer
	if err := controlstate.Seal(ctx, &artifact, st, keys); err != nil {
		t.Fatal(err)
	}
	keyPEMA, err := os.ReadFile(wormA)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(artifact.Bytes(), keyPEMA) {
		t.Fatal("sealed artifact carries the WORM private key in plaintext (G7-6)")
	}

	dirB := t.TempDir()
	wormB := filepath.Join(dirB, "worm-signing-ed25519.pem")
	restored, err := controlstate.Open(ctx, bytes.NewReader(artifact.Bytes()), keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := controlstate.Restore(restored, controlstate.Paths{
		EvidenceSigningKeyFile: filepath.Join(dirB, "evidence.pem"), WormSigningKeyFile: wormB,
	}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if fi, err := os.Stat(wormB); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("restored WORM key = %v, %v; want a 0600 file", fi, err)
	}

	// Host B boots: the loader must reload the original key.
	privB, _, generatedB, err := audit.ResolveWormSigningKey("", wormB, true)
	if err != nil {
		t.Fatal(err)
	}
	if generatedB {
		t.Fatal("host B minted a new WORM key: restored audit signatures would fail verification")
	}
	message := []byte("audit restore signature continuity")
	signed, err := crypto.SignEd25519(privB, message)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := crypto.VerifyEd25519(agentPub, message, signed); err != nil || !ok {
		t.Fatalf("restored WORM signature rejected by original public key: %v", err)
	}

	// A restore never overwrites a live key on the target.
	if err := controlstate.Restore(restored, controlstate.Paths{WormSigningKeyFile: wormB}); err == nil {
		t.Fatal("restore overwrote an existing WORM signing key")
	}
}

// Distribution never started (file configured but never generated) or not
// configured: nothing to carry, and the capture still succeeds. A file that is
// present but unusable fails the capture instead of sealing a broken key.
func TestCaptureWormKeyIsOptionalButNeverBroken(t *testing.T) {
	dir := t.TempDir()
	evidence := filepath.Join(dir, "evidence.pem")
	if _, _, _, err := crypto.LoadOrGenerateEd25519KeyFile(evidence); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", filepath.Join(dir, "never-generated.pem")} {
		st, err := controlstate.Capture(controlstate.Paths{EvidenceSigningKeyFile: evidence, WormSigningKeyFile: path}, "file", nil)
		if err != nil || len(st.WormSigningKeyPEM) != 0 {
			t.Fatalf("path %q: capture = %d key bytes, %v; want none and no error", path, len(st.WormSigningKeyPEM), err)
		}
	}
	broken := filepath.Join(dir, "broken.pem")
	if err := os.WriteFile(broken, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := controlstate.Capture(controlstate.Paths{EvidenceSigningKeyFile: evidence, WormSigningKeyFile: broken}, "file", nil); err == nil {
		t.Fatal("capture sealed an unusable WORM signing key")
	}
}

func TestRestoreWormKeyRejectsMissingDestinationAndInvalidKey(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := controlstate.Restore(controlstate.State{WormSigningKeyPEM: priv}, controlstate.Paths{}); err == nil {
		t.Fatal("silently discarded WORM key")
	}
	out := filepath.Join(t.TempDir(), "worm.pem")
	if err := controlstate.Restore(controlstate.State{WormSigningKeyPEM: []byte("invalid")}, controlstate.Paths{WormSigningKeyFile: out}); err == nil {
		t.Fatal("restored invalid WORM key")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("invalid key wrote a file")
	}
}
