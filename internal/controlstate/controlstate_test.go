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
	"time"

	"github.com/ctlplne/probectl/internal/backup"
	"github.com/ctlplne/probectl/internal/controlstate"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

// TestFreshHostRestorePreservesControlState is the RTO-16 regression: a default
// compose install's control-state (deployment KEK id, incident evidence-signing
// key, agent-CA public bundle) is captured on host A, carried as ONE sealed
// artifact plus the KEK, restored onto a FRESH host B, and host B then boots
// through the REAL load entry points — crypto.LoadOrGenerateEd25519KeyFile for
// the evidence key and tenantcrypto.LoadOrPersistKeyID for the KEK id.
//
// It asserts the behavior the acceptance criterion names:
//   - boot succeeds with no manual step (every load returns, no error);
//   - the evidence-signing key is RELOADED, not minted — so its public
//     fingerprint on B is IDENTICAL to A's (previously signed evidence still
//     verifies). This is the assertion that fails RED before the fix (revert
//     the evidence-key write in controlstate.Restore and it mints a new key
//     with a different fingerprint);
//   - the KEK id reloaded on B equals A's, even against a WRONG boot default;
//   - the agent-CA trust bundle is present on B.
func TestFreshHostRestorePreservesControlState(t *testing.T) {
	ctx := context.Background()

	// --- Host A: a default install on its own fresh dirs. ---
	dirA := t.TempDir()
	keyFileA := filepath.Join(dirA, "envelope.key")
	evidenceFileA := filepath.Join(dirA, "evidence-signing-ed25519.pem")

	// The deployment KEK (SEC-002): generated + persisted on first boot.
	kekB64, generated, err := tenantcrypto.LoadOrGenerateKeyFile(keyFileA)
	if err != nil {
		t.Fatalf("host A generate KEK: %v", err)
	}
	if !generated {
		t.Fatal("host A: expected a freshly generated KEK")
	}
	// The resolved KEK id ("file" for the default compose install), pinned.
	keyIDA, err := tenantcrypto.LoadOrPersistKeyID(keyFileA, "file")
	if err != nil {
		t.Fatalf("host A pin KEK id: %v", err)
	}

	// The incident evidence-signing key: generated + persisted on first boot.
	_, _, evGen, err := crypto.LoadOrGenerateEd25519KeyFile(evidenceFileA)
	if err != nil {
		t.Fatalf("host A generate evidence key: %v", err)
	}
	if !evGen {
		t.Fatal("host A: expected a freshly generated evidence-signing key")
	}
	evidencePEMA, err := os.ReadFile(evidenceFileA)
	if err != nil {
		t.Fatalf("read host A evidence key: %v", err)
	}
	fingerprintA, err := controlstate.EvidenceSigningFingerprint(evidencePEMA)
	if err != nil {
		t.Fatalf("host A fingerprint: %v", err)
	}

	// The agent-CA public trust bundle (root + issuing intermediate certs).
	caBundle := agentCABundle(t)

	// --- Capture + seal the control-state artifact under the KEK. ---
	providerA, err := crypto.NewStaticKeyProviderFromBase64Keyring(keyIDA, kekB64, nil)
	if err != nil {
		t.Fatalf("host A key provider: %v", err)
	}
	st, err := controlstate.Capture(controlstate.Paths{EvidenceSigningKeyFile: evidenceFileA}, keyIDA, caBundle)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	var artifact bytes.Buffer
	if err := controlstate.Seal(ctx, &artifact, st, providerA); err != nil {
		t.Fatalf("seal: %v", err)
	}
	// The sealed artifact never carries the private key in the clear (G7-6).
	if bytes.Contains(artifact.Bytes(), evidencePEMA) {
		t.Fatal("sealed artifact contains the evidence private key in plaintext (G7-6 violation)")
	}

	// --- Host B: a bare fresh host. It has NOTHING but the artifact + the KEK. ---
	dirB := t.TempDir()
	keyFileB := filepath.Join(dirB, "envelope.key")
	evidenceFileB := filepath.Join(dirB, "evidence-signing-ed25519.pem")
	agentCAFileB := filepath.Join(dirB, "agent-ca.crt")
	sidecarB := keyFileB + tenantcrypto.EnvelopeKeyIDSuffix

	// The operator brings the one secret a fresh node needs: the KEK.
	if err := os.WriteFile(keyFileB, []byte(kekB64+"\n"), 0o600); err != nil {
		t.Fatalf("stage KEK on host B: %v", err)
	}

	// Restore: open the artifact with the KEK and write the files into place.
	providerB, err := crypto.NewStaticKeyProviderFromBase64Keyring(keyIDA, kekB64, nil)
	if err != nil {
		t.Fatalf("host B key provider: %v", err)
	}
	restored, err := controlstate.Open(ctx, bytes.NewReader(artifact.Bytes()), providerB)
	if err != nil {
		t.Fatalf("open artifact on host B: %v", err)
	}
	if err := controlstate.Restore(restored, controlstate.Paths{
		EvidenceSigningKeyFile: evidenceFileB,
		AgentCABundleFile:      agentCAFileB,
		EnvelopeKeyIDSidecar:   sidecarB,
	}); err != nil {
		t.Fatalf("restore on host B: %v", err)
	}

	// --- Boot host B through the REAL load entry points. ---

	// (a) Evidence-signing key: it must be RELOADED, not minted.
	_, _, evGenB, err := crypto.LoadOrGenerateEd25519KeyFile(evidenceFileB)
	if err != nil {
		t.Fatalf("host B load evidence key: %v", err)
	}
	if evGenB {
		t.Fatal("host B minted a NEW evidence-signing key on boot — the restore did not put the original in place (manual step would be required)")
	}
	evidencePEMB, err := os.ReadFile(evidenceFileB)
	if err != nil {
		t.Fatalf("read host B evidence key: %v", err)
	}
	fingerprintB, err := controlstate.EvidenceSigningFingerprint(evidencePEMB)
	if err != nil {
		t.Fatalf("host B fingerprint: %v", err)
	}
	// THE assertion: the fingerprint is unchanged across the restore.
	if fingerprintB != fingerprintA {
		t.Fatalf("evidence-signing fingerprint changed across restore: A=%s B=%s — previously signed evidence would no longer verify", fingerprintA, fingerprintB)
	}

	// (b) KEK id: the restored sidecar is authoritative, even against a WRONG
	//     boot default (operator forgot PROBECTL_ENVELOPE_KEY_ID on the restore).
	bootID, err := tenantcrypto.LoadOrPersistKeyID(keyFileB, "wrong-boot-default")
	if err != nil {
		t.Fatalf("host B reload KEK id: %v", err)
	}
	if bootID != keyIDA {
		t.Fatalf("KEK id reloaded on host B = %q, want %q (a renumber would strand the restored dv1 values)", bootID, keyIDA)
	}

	// (c) Agent-CA trust bundle present and byte-for-byte identical.
	gotCA, err := os.ReadFile(agentCAFileB)
	if err != nil {
		t.Fatalf("host B agent-CA bundle missing (would need a manual `agent-ca export`): %v", err)
	}
	if !bytes.Equal(gotCA, caBundle) {
		t.Fatal("restored agent-CA bundle differs from the captured one")
	}
}

// TestOpenRejectsWrongKEK proves the artifact is genuinely sealed: a different
// KEK cannot open it (fail closed, no silent plaintext).
func TestOpenRejectsWrongKEK(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	evidenceFile := filepath.Join(dir, "evidence.pem")
	if _, _, _, err := crypto.LoadOrGenerateEd25519KeyFile(evidenceFile); err != nil {
		t.Fatalf("generate evidence key: %v", err)
	}
	right := staticProvider(t, "file")
	wrong := staticProvider(t, "file")

	st, err := controlstate.Capture(controlstate.Paths{EvidenceSigningKeyFile: evidenceFile}, "file", nil)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	var artifact bytes.Buffer
	if err := controlstate.Seal(ctx, &artifact, st, right); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := controlstate.Open(ctx, bytes.NewReader(artifact.Bytes()), wrong); err == nil {
		t.Fatal("Open accepted a WRONG KEK — a sealed artifact must fail closed")
	}
}

// TestSealRefusesWithoutEvidenceKey guards the invariant that the artifact's
// reason to exist — preserving the evidence fingerprint — is always met.
func TestSealRefusesWithoutEvidenceKey(t *testing.T) {
	err := controlstate.Seal(context.Background(), &bytes.Buffer{}, controlstate.State{EnvelopeKeyID: "file"}, staticProvider(t, "file"))
	if err == nil {
		t.Fatal("Seal must refuse an artifact with no evidence-signing key")
	}
}

func staticProvider(t *testing.T, keyID string) backup.KeyProvider {
	t.Helper()
	raw, err := crypto.Random(crypto.KeySize)
	if err != nil {
		t.Fatalf("random KEK: %v", err)
	}
	p, err := crypto.NewStaticKeyringProvider(keyID, raw, nil)
	if err != nil {
		t.Fatalf("key provider: %v", err)
	}
	return p
}

// agentCABundle builds a realistic root+intermediate public trust bundle.
func agentCABundle(t *testing.T) []byte {
	t.Helper()
	root, err := crypto.GenerateRootCA("probectl-test-root", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("root CA: %v", err)
	}
	inter, err := root.IssueIntermediate("probectl-test-intermediate", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("intermediate CA: %v", err)
	}
	var out bytes.Buffer
	out.Write(root.CertPEM())
	out.Write(inter.CertPEM())
	return out.Bytes()
}
