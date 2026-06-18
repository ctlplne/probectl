// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"bytes"
	"context"
	"encoding/base64"
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
