// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/backup"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
)

// backup-seal / backup-open (OPS-002): stdin→stdout envelope-encryption
// filters so a backup CronJob can pipe a dump straight through encryption —
// `pg_dump ... | probectl-control backup-seal --key-file=K > out.pbk` — and
// nothing ever lands on disk in plaintext. Restore: `probectl-control
// backup-open --key-file=K < out.pbk | pg_restore ...`.
//
// The key is the SAME deployment KEK as the at-rest envelope (Sprint 8): a
// base64 env value (PROBECTL_ENVELOPE_KEY) or a key file
// (PROBECTL_ENVELOPE_KEY_FILE / --key-file), so a restore on a fresh node
// only needs that one key.

func backupSeal(args []string) error { return runBackup(args, true) }
func backupOpen(args []string) error { return runBackup(args, false) }
func backupRewrap(args []string) error {
	fs := flag.NewFlagSet("backup-rewrap", flag.ContinueOnError)
	keyFile := fs.String("key-file", os.Getenv("PROBECTL_ENVELOPE_KEY_FILE"), "path to the base64 KEK file (or set PROBECTL_ENVELOPE_KEY)")
	defKeyID := os.Getenv("PROBECTL_ENVELOPE_KEY_ID")
	if defKeyID == "" {
		defKeyID = "file"
	}
	keyID := fs.String("key-id", defKeyID, "active KEK id stamped into the rewrapped container header")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keys, err := backupKeyProvider(*keyFile, *keyID)
	if err != nil {
		return err
	}
	if err := backup.Rewrap(context.Background(), os.Stdout, os.Stdin, keys, keys); err != nil {
		return fmt.Errorf("backup-rewrap: %w", err)
	}
	return nil
}

func runBackup(args []string, seal bool) error {
	name := "backup-open"
	if seal {
		name = "backup-seal"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	keyFile := fs.String("key-file", os.Getenv("PROBECTL_ENVELOPE_KEY_FILE"), "path to the base64 KEK file (or set PROBECTL_ENVELOPE_KEY)")
	defKeyID := os.Getenv("PROBECTL_ENVELOPE_KEY_ID")
	if defKeyID == "" {
		defKeyID = "file"
	}
	keyID := fs.String("key-id", defKeyID, "KEK id stamped into / matched against the container header")
	if err := fs.Parse(args); err != nil {
		return err
	}

	keys, err := backupKeyProvider(*keyFile, *keyID)
	if err != nil {
		return err
	}

	ctx := context.Background()
	if seal {
		if err := backup.Seal(ctx, os.Stdout, os.Stdin, keys); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	}
	if err := backup.Open(ctx, os.Stdout, os.Stdin, keys); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// backupKeyProvider builds the KEK key provider from the env key or a key
// file (the Sprint 8 sources), failing closed if neither is present — a
// keyless backup would defeat OPS-002.
func backupKeyProvider(keyFile, keyID string) (crypto.KeyProvider, error) {
	if b64 := os.Getenv("PROBECTL_ENVELOPE_KEY"); b64 != "" {
		openerKeys, err := parseEnvelopeOpenerKeys(os.Getenv("PROBECTL_ENVELOPE_OPENER_KEYS"))
		if err != nil {
			return nil, err
		}
		return crypto.NewStaticKeyProviderFromBase64Keyring(keyID, b64, openerKeys)
	}
	if keyFile != "" {
		// LoadOrGenerate would MINT a key on a restore node that lacks it,
		// silently producing an unreadable mismatch — for backups we require
		// the existing key, so read it without generating.
		b64, err := tenantcrypto.LoadExistingKeyFile(keyFile)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("backup key file %q did not exist — refusing to MINT a key for a backup (a sealed backup needs its ORIGINAL KEK; provide the existing key): %w", keyFile, err)
			}
			return nil, fmt.Errorf("backup key file: %w", err)
		}
		openerKeys, err := parseEnvelopeOpenerKeys(os.Getenv("PROBECTL_ENVELOPE_OPENER_KEYS"))
		if err != nil {
			return nil, err
		}
		return crypto.NewStaticKeyProviderFromBase64Keyring(keyID, b64, openerKeys)
	}
	return nil, fmt.Errorf("no envelope key: set PROBECTL_ENVELOPE_KEY or --key-file (OPS-002 — backups are never written unencrypted)")
}

func parseEnvelopeOpenerKeys(spec string) (map[string]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	out := map[string]string{}
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		keyID, keyB64, ok := strings.Cut(item, "=")
		keyID = strings.TrimSpace(keyID)
		keyB64 = strings.TrimSpace(keyB64)
		if !ok || keyID == "" || keyB64 == "" {
			return nil, fmt.Errorf("envelope opener key %q must be keyID=base64", item)
		}
		if _, exists := out[keyID]; exists {
			return nil, fmt.Errorf("duplicate envelope opener key id %q", keyID)
		}
		out[keyID] = keyB64
	}
	return out, nil
}
