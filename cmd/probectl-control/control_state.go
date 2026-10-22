// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/controlstate"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/enroll"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

// backup-control-state / restore-control-state (RTO-16): the fresh-host restore
// companion to the store backups. The store dumps (Postgres/ClickHouse/object
// tree) carry the data; this pair carries the control-state key material that
// lives on the controldata volume beside them — the deployment KEK id, the
// incident evidence-signing key, and the agent-CA public trust bundle — so a
// restore onto a fresh host boots with NO manual steps and the evidence-signing
// fingerprint UNCHANGED (previously signed evidence still verifies).
//
// The artifact is envelope-encrypted under the deployment KEK (internal/backup),
// so the evidence private key is never written in the clear (G7-6) and a fresh
// node needs the same single secret — the KEK — it already needs for the DB.

// backupControlState captures the control-state into a sealed artifact on
// stdout. It runs as a DB-backed one-shot so it can read the agent-CA public
// bundle from the authoritative source (the database); the evidence key and
// KEK id come from the resolved config. The KEK itself is NOT captured — it is
// the restore's bootstrap secret, brought separately, and sealing it under
// itself would be meaningless.
func backupControlState(ctx context.Context, cfg *config.Config, db *store.DB) error {
	provider, err := controlStateKeyProvider(cfg)
	if err != nil {
		return err
	}
	if cfg.EvidenceSigningKeyFile == "" {
		return errors.New("backup-control-state: no evidence-signing key file is configured (PROBECTL_EVIDENCE_SIGNING_KEY_FILE). " +
			"A deployment that injects PROBECTL_EVIDENCE_SIGNING_KEY from a secret manager re-injects it on the restored host and needs no control-state capture")
	}

	// The agent CA trust bundle is public material in the database; export it so
	// the restored host has PROBECTL_AGENT_TLS_CA_FILE without a manual
	// `agent-ca export`. A deployment that never initialized the CA simply omits
	// it (the artifact degrades gracefully).
	var caBundle []byte
	if bundle, berr := enroll.PublicBundle(ctx, db.Pool()); berr == nil {
		caBundle = bundle
	} else if !errors.Is(berr, store.ErrAgentCANotInitialized) {
		return fmt.Errorf("backup-control-state: export agent CA bundle: %w", berr)
	}

	st, err := controlstate.Capture(controlstate.Paths{
		EvidenceSigningKeyFile: cfg.EvidenceSigningKeyFile,
		TestSyncSigningKeyFile: testSyncKeyFileToCapture(cfg),
	}, cfg.EnvelopeKeyID, caBundle)
	if err != nil {
		return fmt.Errorf("backup-control-state: %w", err)
	}
	if err := controlstate.Seal(ctx, os.Stdout, st, provider); err != nil {
		return fmt.Errorf("backup-control-state: %w", err)
	}
	return nil
}

// testSyncKeyFileToCapture names the test-bundle signing key file to seal (G9).
// A deployment that injects PROBECTL_TESTSYNC_SIGNING_KEY from a secret manager
// re-injects it on the restored host — that is the key serve uses, so a stale
// file beside it is not captured.
func testSyncKeyFileToCapture(cfg *config.Config) string {
	if strings.TrimSpace(cfg.TestSyncSigningKey) != "" {
		return ""
	}
	return cfg.TestSyncSigningKeyFile
}

// restoreControlState opens a sealed control-state artifact from stdin and
// writes its files onto a fresh controldata volume BEFORE boot. It needs no
// database — only the KEK (the same secret backup-open needs) — so it runs as
// an early one-shot, matching the restore runbook's `PROBECTL_ENVELOPE_KEY=...
// probectl-control backup-open` step. Target paths default to the shipped
// compose env and are overridable by flag.
func restoreControlState(args []string, stdin io.Reader) error {
	fs := flag.NewFlagSet("restore-control-state", flag.ContinueOnError)
	keyFile := fs.String("key-file", os.Getenv("PROBECTL_ENVELOPE_KEY_FILE"), "path to the base64 KEK file (or set PROBECTL_ENVELOPE_KEY)")
	defKeyID := os.Getenv("PROBECTL_ENVELOPE_KEY_ID")
	if defKeyID == "" {
		defKeyID = "file"
	}
	keyID := fs.String("key-id", defKeyID, "active KEK id used to build the opener keyring")
	evidenceOut := fs.String("evidence-key-out", os.Getenv("PROBECTL_EVIDENCE_SIGNING_KEY_FILE"), "where to write the restored evidence-signing key (PROBECTL_EVIDENCE_SIGNING_KEY_FILE)")
	agentCAOut := fs.String("agent-ca-out", os.Getenv("PROBECTL_AGENT_TLS_CA_FILE"), "where to write the restored agent-CA trust bundle (PROBECTL_AGENT_TLS_CA_FILE)")
	testSyncOut := fs.String("testsync-key-out", os.Getenv("PROBECTL_TESTSYNC_SIGNING_KEY_FILE"), "where to write the restored test-bundle signing key (PROBECTL_TESTSYNC_SIGNING_KEY_FILE)")
	sidecarOut := fs.String("key-id-out", "", "where to write the KEK id sidecar (default: <PROBECTL_ENVELOPE_KEY_FILE>.id)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sidecarOut == "" && *keyFile != "" {
		*sidecarOut = *keyFile + tenantcrypto.EnvelopeKeyIDSuffix
	}

	provider, err := backupKeyProvider(*keyFile, *keyID)
	if err != nil {
		return fmt.Errorf("restore-control-state: %w", err)
	}
	st, err := controlstate.Open(context.Background(), stdin, provider)
	if err != nil {
		return fmt.Errorf("restore-control-state: %w", err)
	}
	if err := controlstate.Restore(st, controlstate.Paths{
		EvidenceSigningKeyFile: *evidenceOut,
		AgentCABundleFile:      *agentCAOut,
		EnvelopeKeyIDSidecar:   *sidecarOut,
		TestSyncSigningKeyFile: *testSyncOut,
	}); err != nil {
		return fmt.Errorf("restore-control-state: %w", err)
	}
	fp, err := controlstate.EvidenceSigningFingerprint(st.EvidenceSigningKeyPEM)
	if err != nil {
		return fmt.Errorf("restore-control-state: %w", err)
	}
	fmt.Fprintf(os.Stderr, "restored control state: evidence-signing fingerprint %s, key id %q\n", fp, st.EnvelopeKeyID)
	if *evidenceOut != "" {
		fmt.Fprintln(os.Stderr, "  evidence-signing key ->", *evidenceOut)
	}
	if len(st.AgentCABundlePEM) > 0 && *agentCAOut != "" {
		fmt.Fprintln(os.Stderr, "  agent-CA trust bundle ->", *agentCAOut)
	}
	reportRestoredTestSyncKey(st, *testSyncOut)
	fmt.Fprintln(os.Stderr, "boot the control plane normally — it reloads this material instead of generating fresh.")
	return nil
}

// controlStateKeyProvider builds the deployment KEK provider from the resolved
// config (the sealer is already installed; this is the matching crypto.KeyProvider
// for the artifact's envelope). It fails closed when no KEK is resolvable — a
// keyless-dev deployment has no at-rest encryption to preserve.
func controlStateKeyProvider(cfg *config.Config) (crypto.KeyProvider, error) {
	if cfg.EnvelopeKey == "" {
		return nil, errors.New("backup-control-state: no deployment envelope key is resolved — there is no at-rest key material to capture (keyless-dev)")
	}
	openerKeys, err := parseEnvelopeOpenerKeys(cfg.EnvelopeOpenerKeys)
	if err != nil {
		return nil, err
	}
	return crypto.NewStaticKeyProviderFromBase64Keyring(cfg.EnvelopeKeyID, cfg.EnvelopeKey, openerKeys)
}

// reportRestoredTestSyncKey tells the operator where the test-bundle signing
// key went (G9), or that the artifact carried one with nowhere to put it — a
// restore that silently dropped it would leave every agent refusing bundles.
func reportRestoredTestSyncKey(st controlstate.State, out string) {
	if len(st.TestSyncSigningKeyPEM) == 0 {
		return
	}
	fp, err := controlstate.EvidenceSigningFingerprint(st.TestSyncSigningKeyPEM)
	if err != nil {
		fp = "unknown"
	}
	if out == "" {
		fmt.Fprintf(os.Stderr, "  WARNING: the artifact carries the test-bundle signing key (%s) but no -testsync-key-out / "+
			"PROBECTL_TESTSYNC_SIGNING_KEY_FILE is set; agents will refuse bundles signed by a new key\n", fp)
		return
	}
	fmt.Fprintf(os.Stderr, "  test-bundle signing key (%s) -> %s\n", fp, out)
}
