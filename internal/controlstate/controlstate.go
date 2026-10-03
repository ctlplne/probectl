// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package controlstate is the fresh-host restore artifact for the control
// plane's non-database key material (RTO-16).
//
// The shipped backups cover the stores — Postgres, ClickHouse, the object tree
// (docs/ops/backup-restore.md). They do NOT cover the control-state that lives
// on the controldata volume beside them: the deployment envelope KEY ID, the
// incident evidence-signing key, and the agent-CA public trust bundle. Lose
// those on a fresh host and the control plane still boots — but it boots WRONG:
// it mints a NEW evidence-signing key (so every previously signed evidence
// package fails verification, because the public fingerprint changed), it can
// renumber the KEK id (so the restored dv1 values no longer open), and the
// agent-CA trust bundle the gRPC listener verifies clients against is missing
// until an operator re-exports it. Each is an undocumented manual step on a
// restore nobody rehearses under stress.
//
// This package makes that state a single, sealed artifact: `backup-control-state`
// captures it, `restore-control-state` writes it back onto a fresh controldata
// volume BEFORE boot, and the ordinary boot path then RELOADS the same key
// material instead of generating fresh — same evidence fingerprint, same key
// id, agent CA present, zero manual steps.
//
// The artifact is envelope-encrypted through internal/backup (a fresh DEK per
// artifact, wrapped by the deployment KEK; crypto only via internal/crypto —
// docs/guardrails.md G7-3). The evidence-signing PRIVATE key therefore never
// lands in the artifact in plaintext (G7-6): opening it needs the same KEK as
// the rest of the restore, the single secret a fresh node already must carry.
package controlstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ctlplne/probectl/internal/backup"
	"github.com/ctlplne/probectl/internal/crypto"
)

// manifestVersion is the control-state artifact schema version. Open refuses a
// version it does not understand rather than silently restoring partial state.
const manifestVersion = 1

// maxManifest bounds the decrypted manifest read on the restore path so a
// crafted (or corrupt) artifact cannot force an unbounded allocation. The real
// manifest is a few hundred bytes of evidence key plus a few KB of CA PEM.
const maxManifest = 4 << 20 // 4 MiB

// State is the control-plane key material that the store backups do not carry.
// Every field is optional so the artifact degrades gracefully: a deployment
// that never initialized the agent CA simply omits that field.
type State struct {
	Version int `json:"version"`
	// EnvelopeKeyID is the deployment KEK id the source sealed its at-rest data
	// under. It is NOT secret (it is stamped in the clear in every dv1 value and
	// .pbk header); restoring it pins the id so the restored values keep opening.
	EnvelopeKeyID string `json:"envelope_key_id,omitempty"`
	// EvidenceSigningKeyPEM is the PKCS#8 Ed25519 private key that signs
	// immutable incident evidence packages. Restoring it keeps the public
	// fingerprint UNCHANGED so previously signed evidence still verifies.
	EvidenceSigningKeyPEM []byte `json:"evidence_signing_key_pem,omitempty"`
	// AgentCABundlePEM is the agent-CA PUBLIC trust bundle (root + issuing
	// intermediate certificates) the agent gRPC listener verifies clients
	// against (PROBECTL_AGENT_TLS_CA_FILE). Public material only — never the
	// sealed intermediate key, which rides the restored database.
	AgentCABundlePEM []byte `json:"agent_ca_bundle_pem,omitempty"`
}

// Paths names where the control-state files live on the controldata volume.
// They mirror the shipped compose env (PROBECTL_EVIDENCE_SIGNING_KEY_FILE,
// PROBECTL_AGENT_TLS_CA_FILE) and the KEK-id sidecar beside the envelope key.
type Paths struct {
	EvidenceSigningKeyFile string
	AgentCABundleFile      string
	EnvelopeKeyIDSidecar   string
}

// Seal writes st to w as a sealed control-state artifact: the manifest is
// JSON-encoded and envelope-encrypted under keys (the deployment KEK). The
// evidence-signing private key is in the manifest, so the artifact is only ever
// written through this encrypting path (G7-6 — no plaintext private key).
func Seal(ctx context.Context, w io.Writer, st State, keys backup.KeyProvider) error {
	if st.Version == 0 {
		st.Version = manifestVersion
	}
	if len(st.EvidenceSigningKeyPEM) == 0 {
		return errors.New("controlstate: refusing to seal an artifact with no evidence-signing key — the whole point is to preserve its fingerprint across a restore")
	}
	manifest, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("controlstate: marshal manifest: %w", err)
	}
	if err := backup.Seal(ctx, w, bytes.NewReader(manifest), keys); err != nil {
		return fmt.Errorf("controlstate: seal: %w", err)
	}
	return nil
}

// Open reads a sealed control-state artifact from r and returns the manifest.
// It unseals through the same KEK as the rest of the restore and bounds the
// decrypted size (maxManifest) before parsing untrusted input.
func Open(ctx context.Context, r io.Reader, keys backup.KeyProvider) (State, error) {
	sink := &cappedBuffer{max: maxManifest}
	if err := backup.Open(ctx, sink, r, keys); err != nil {
		return State{}, fmt.Errorf("controlstate: open: %w", err)
	}
	var st State
	if err := json.Unmarshal(sink.buf.Bytes(), &st); err != nil {
		return State{}, fmt.Errorf("controlstate: parse manifest: %w", err)
	}
	if st.Version != manifestVersion {
		return State{}, fmt.Errorf("controlstate: unsupported artifact version %d (this build understands %d)", st.Version, manifestVersion)
	}
	return st, nil
}

// Capture gathers the on-disk control-state into a State. The evidence-signing
// key is required (it is the state the store backups cannot carry); the agent
// CA bundle is taken from agentCABundle when non-empty (callers read it from
// the database or an exported file). keyID pins the deployment KEK id.
func Capture(p Paths, keyID string, agentCABundle []byte) (State, error) {
	if p.EvidenceSigningKeyFile == "" {
		return State{}, errors.New("controlstate: no evidence-signing key file configured (PROBECTL_EVIDENCE_SIGNING_KEY_FILE) — nothing to capture")
	}
	evPEM, err := os.ReadFile(p.EvidenceSigningKeyFile)
	if err != nil {
		return State{}, fmt.Errorf("controlstate: read evidence-signing key %s: %w", p.EvidenceSigningKeyFile, err)
	}
	if _, err := crypto.PublicPEMFromPrivate(evPEM); err != nil {
		return State{}, fmt.Errorf("controlstate: evidence-signing key %s is not a usable Ed25519 private key: %w", p.EvidenceSigningKeyFile, err)
	}
	return State{
		Version:               manifestVersion,
		EnvelopeKeyID:         keyID,
		EvidenceSigningKeyPEM: evPEM,
		AgentCABundlePEM:      agentCABundle,
	}, nil
}

// Restore writes the control-state back onto a fresh controldata volume at p.
// The private evidence key lands 0600 (the same at-rest representation the boot
// path generates); the public CA bundle and the key-id sidecar land 0644 and
// 0600. Writes are atomic and never clobber an existing evidence key — a
// restore populates a fresh node, it does not overwrite a live signing key.
func Restore(st State, p Paths) error {
	if len(st.EvidenceSigningKeyPEM) > 0 && p.EvidenceSigningKeyFile != "" {
		if err := writeNewFile(p.EvidenceSigningKeyFile, st.EvidenceSigningKeyPEM, 0o600); err != nil {
			return fmt.Errorf("controlstate: restore evidence-signing key: %w", err)
		}
	}
	if len(st.AgentCABundlePEM) > 0 && p.AgentCABundleFile != "" {
		if err := writeAtomic(p.AgentCABundleFile, st.AgentCABundlePEM, 0o644); err != nil {
			return fmt.Errorf("controlstate: restore agent-CA bundle: %w", err)
		}
	}
	if st.EnvelopeKeyID != "" && p.EnvelopeKeyIDSidecar != "" {
		if err := writeAtomic(p.EnvelopeKeyIDSidecar, []byte(st.EnvelopeKeyID+"\n"), 0o600); err != nil {
			return fmt.Errorf("controlstate: restore envelope key-id: %w", err)
		}
	}
	return nil
}

// EvidenceSigningFingerprint renders the stable public fingerprint of an
// Ed25519 private-key PEM, in the EXACT form the serve path logs
// ("sha256:<hex>"), so a restore can be proven to preserve it.
func EvidenceSigningFingerprint(privPEM []byte) (string, error) {
	pubPEM, err := crypto.PublicPEMFromPrivate(privPEM)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", crypto.Hash(pubPEM)), nil
}

// writeNewFile writes an atomic file but refuses to overwrite an existing one
// (used for the private signing key: a restore never clobbers a live key).
func writeNewFile(path string, data []byte, mode os.FileMode) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists — restore populates a fresh host, it does not overwrite a live key", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeAtomic(path, data, mode)
}

// writeAtomic writes data to path via a temp file + rename, creating the parent
// directory 0700. The temp file carries the final mode before the rename.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// cappedBuffer collects decrypted bytes up to max, erroring past it so a
// hostile artifact cannot force an unbounded allocation on restore.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.max {
		return 0, fmt.Errorf("controlstate: artifact exceeds %d-byte cap (corrupt or not a control-state artifact)", c.max)
	}
	return c.buf.Write(p)
}
