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

	"github.com/ctlplne/probectl/internal/controlstate"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/testsync"
)

// TestFreshHostRestoreKeepsAgentsVerifyingTestBundles is the G9 restore
// regression: host A generates its test-bundle signing key on first boot, and
// every agent holds A's PUBLIC half (testsync.pub, written at enrollment). The
// control state is sealed, restored onto a fresh host B, and B boots through
// the real loader. A bundle B signs must verify against A's public key — the
// one the agents hold — or every agent refuses every bundle after a restore.
func TestFreshHostRestoreKeepsAgentsVerifyingTestBundles(t *testing.T) {
	ctx := context.Background()
	dirA := t.TempDir()
	evidenceA := filepath.Join(dirA, "evidence.pem")
	testsyncA := filepath.Join(dirA, "testsync-signing-ed25519.pem")
	if _, _, _, err := crypto.LoadOrGenerateEd25519KeyFile(evidenceA); err != nil {
		t.Fatal(err)
	}
	_, agentPub, generated, err := crypto.LoadOrGenerateEd25519KeyFile(testsyncA)
	if err != nil || !generated {
		t.Fatalf("host A first-boot test-bundle key: generated=%v err=%v", generated, err)
	}
	keys := staticProvider(t, "file")

	st, err := controlstate.Capture(controlstate.Paths{
		EvidenceSigningKeyFile: evidenceA, TestSyncSigningKeyFile: testsyncA,
	}, "file", nil)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	var artifact bytes.Buffer
	if err := controlstate.Seal(ctx, &artifact, st, keys); err != nil {
		t.Fatal(err)
	}
	keyPEMA, err := os.ReadFile(testsyncA)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(artifact.Bytes(), keyPEMA) {
		t.Fatal("sealed artifact carries the test-bundle private key in plaintext (G7-6)")
	}

	dirB := t.TempDir()
	testsyncB := filepath.Join(dirB, "testsync-signing-ed25519.pem")
	restored, err := controlstate.Open(ctx, bytes.NewReader(artifact.Bytes()), keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := controlstate.Restore(restored, controlstate.Paths{
		EvidenceSigningKeyFile: filepath.Join(dirB, "evidence.pem"), TestSyncSigningKeyFile: testsyncB,
	}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if fi, err := os.Stat(testsyncB); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("restored test-bundle key = %v, %v; want a 0600 file", fi, err)
	}

	// Host B boots: the loader must RELOAD, not mint.
	privB, _, generatedB, err := crypto.LoadOrGenerateEd25519KeyFile(testsyncB)
	if err != nil {
		t.Fatal(err)
	}
	if generatedB {
		t.Fatal("host B minted a new test-bundle signing key: every enrolled agent would refuse its bundles")
	}
	signed, err := testsync.Sign(testsync.Bundle{TenantID: "t-1", Epoch: 7, Tests: []testsync.Test{
		{ID: "x", Type: "http", Target: "https://example.com", IntervalSeconds: 30},
	}}, privB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testsync.Verify(signed, agentPub, 0); err != nil {
		t.Fatalf("a bundle signed by the restored deployment does not verify against the public key agents hold: %v", err)
	}

	// A restore never overwrites a live key on the target.
	if err := controlstate.Restore(restored, controlstate.Paths{TestSyncSigningKeyFile: testsyncB}); err == nil {
		t.Fatal("restore overwrote an existing test-bundle signing key")
	}
}

// Distribution never started (file configured but never generated) or not
// configured: nothing to carry, and the capture still succeeds. A file that is
// present but unusable fails the capture instead of sealing a broken key.
func TestCaptureTestSyncKeyIsOptionalButNeverBroken(t *testing.T) {
	dir := t.TempDir()
	evidence := filepath.Join(dir, "evidence.pem")
	if _, _, _, err := crypto.LoadOrGenerateEd25519KeyFile(evidence); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", filepath.Join(dir, "never-generated.pem")} {
		st, err := controlstate.Capture(controlstate.Paths{EvidenceSigningKeyFile: evidence, TestSyncSigningKeyFile: path}, "file", nil)
		if err != nil || len(st.TestSyncSigningKeyPEM) != 0 {
			t.Fatalf("path %q: capture = %d key bytes, %v; want none and no error", path, len(st.TestSyncSigningKeyPEM), err)
		}
	}
	broken := filepath.Join(dir, "broken.pem")
	if err := os.WriteFile(broken, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := controlstate.Capture(controlstate.Paths{EvidenceSigningKeyFile: evidence, TestSyncSigningKeyFile: broken}, "file", nil); err == nil {
		t.Fatal("capture sealed an unusable test-bundle signing key")
	}
}
