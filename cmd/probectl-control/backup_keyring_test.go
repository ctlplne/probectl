// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/backup"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

func TestBackupKeyProviderUsesEnvelopeOpenerKeys(t *testing.T) {
	ctx := context.Background()
	oldKEK, err := crypto.Random(crypto.KeySize)
	if err != nil {
		t.Fatal(err)
	}
	newKEK, err := crypto.Random(crypto.KeySize)
	if err != nil {
		t.Fatal(err)
	}
	oldKeys, err := crypto.NewStaticKeyProvider("old", oldKEK)
	if err != nil {
		t.Fatal(err)
	}
	var sealed bytes.Buffer
	if err := backup.Seal(ctx, &sealed, strings.NewReader("historic backup"), oldKeys); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PROBECTL_ENVELOPE_KEY", base64.StdEncoding.EncodeToString(newKEK))
	t.Setenv("PROBECTL_ENVELOPE_OPENER_KEYS", "old="+base64.StdEncoding.EncodeToString(oldKEK))
	keyring, err := backupKeyProvider("", "new")
	if err != nil {
		t.Fatal(err)
	}
	var restored bytes.Buffer
	if err := backup.Open(ctx, &restored, bytes.NewReader(sealed.Bytes()), keyring); err != nil {
		t.Fatalf("backup-open keyring failed: %v", err)
	}
	if restored.String() != "historic backup" {
		t.Fatalf("restored = %q", restored.String())
	}
}

func TestBackupKeyProviderMissingKeyFileDoesNotMint(t *testing.T) {
	t.Setenv("PROBECTL_ENVELOPE_KEY", "")
	t.Setenv("PROBECTL_ENVELOPE_OPENER_KEYS", "")
	path := filepath.Join(t.TempDir(), "missing", "envelope.key")

	if _, err := backupKeyProvider(path, "file"); err == nil ||
		!strings.Contains(err.Error(), "refusing to MINT a key for a backup") {
		t.Fatalf("missing backup key file must fail closed with no minting, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("backupKeyProvider must not create %s; stat err=%v", path, err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("backupKeyProvider must not create parent dir %s; stat err=%v", filepath.Dir(path), err)
	}
}

func TestParseEnvelopeOpenerKeys(t *testing.T) {
	got, err := parseEnvelopeOpenerKeys("old=abc=, older = def==")
	if err != nil {
		t.Fatal(err)
	}
	if got["old"] != "abc=" || got["older"] != "def==" {
		t.Fatalf("parsed = %#v", got)
	}
	if _, err := parseEnvelopeOpenerKeys("missing-equals"); err == nil {
		t.Fatal("malformed opener spec must fail")
	}
	if _, err := parseEnvelopeOpenerKeys("old=a,old=b"); err == nil {
		t.Fatal("duplicate opener id must fail")
	}
}
