// SPDX-License-Identifier: LicenseRef-probectl-TBD

package backup

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

func testKeys(t *testing.T) KeyProvider {
	t.Helper()
	kek, err := crypto.Random(crypto.KeySize)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := crypto.NewStaticKeyProvider("backup-test", kek)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// OPS-002: a backup round-trips through the encrypted container, and the
// sealed bytes NEVER contain the plaintext — tenant telemetry never lands on
// disk in the clear. Restore from the encrypted backup is exact.
func TestSealOpenRoundTripAndNoPlaintext(t *testing.T) {
	keys := testKeys(t)
	ctx := context.Background()

	// A multi-chunk "dump" with a recognizable secret marker.
	secret := "TENANT-SECRET-acct-4111111111111111"
	var plain bytes.Buffer
	plain.WriteString("PGDMP fake header\n")
	for i := 0; i < 3000; i++ { // > chunkSize to exercise chunking
		plain.WriteString("row data " + secret + " more data\n")
	}
	original := plain.Bytes()

	var sealed bytes.Buffer
	if err := Seal(ctx, &sealed, bytes.NewReader(original), keys); err != nil {
		t.Fatalf("seal: %v", err)
	}

	// The on-disk artifact must NOT contain the plaintext or its secret.
	if bytes.Contains(sealed.Bytes(), []byte(secret)) {
		t.Fatal("OPS-002 VIOLATION: plaintext secret present in the sealed backup")
	}
	if bytes.Contains(sealed.Bytes(), []byte("PGDMP fake header")) {
		t.Fatal("OPS-002 VIOLATION: plaintext header present in the sealed backup")
	}
	if sealed.Len() <= len(magic) {
		t.Fatal("sealed output suspiciously small")
	}

	// Restore is byte-exact.
	var restored bytes.Buffer
	if err := Open(ctx, &restored, bytes.NewReader(sealed.Bytes()), keys); err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(restored.Bytes(), original) {
		t.Fatalf("restore mismatch: %d vs %d bytes", restored.Len(), len(original))
	}
}

// The empty backup still round-trips (clean header + terminator only).
func TestSealOpenEmpty(t *testing.T) {
	keys := testKeys(t)
	ctx := context.Background()
	var sealed bytes.Buffer
	if err := Seal(ctx, &sealed, bytes.NewReader(nil), keys); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Open(ctx, &out, bytes.NewReader(sealed.Bytes()), keys); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("empty backup restored %d bytes", out.Len())
	}
}

// A wrong KEK cannot open the backup (the wrapped DEK fails to unwrap).
func TestOpenWrongKeyFails(t *testing.T) {
	ctx := context.Background()
	var sealed bytes.Buffer
	if err := Seal(ctx, &sealed, strings.NewReader("hello backup"), testKeys(t)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Open(ctx, &out, bytes.NewReader(sealed.Bytes()), testKeys(t)); err == nil {
		t.Fatal("a different KEK must not open the backup")
	}
}

func TestOpenUsesHeaderKeyIDForRotationKeyring(t *testing.T) {
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
	var oldContainer bytes.Buffer
	if err := Seal(ctx, &oldContainer, strings.NewReader("old backup"), oldKeys); err != nil {
		t.Fatal(err)
	}

	newKeyring, err := crypto.NewStaticKeyringProvider("new", newKEK, map[string][]byte{"old": oldKEK})
	if err != nil {
		t.Fatal(err)
	}
	var restored bytes.Buffer
	if err := Open(ctx, &restored, bytes.NewReader(oldContainer.Bytes()), newKeyring); err != nil {
		t.Fatalf("open old backup with rotation keyring: %v", err)
	}
	if restored.String() != "old backup" {
		t.Fatalf("restored = %q", restored.String())
	}

	currentOnly, err := crypto.NewStaticKeyProvider("new", newKEK)
	if err != nil {
		t.Fatal(err)
	}
	if err := Open(ctx, &bytes.Buffer{}, bytes.NewReader(oldContainer.Bytes()), currentOnly); err == nil {
		t.Fatal("current-only key must not open a backup sealed with an old key id")
	}

	var newContainer bytes.Buffer
	if err := Seal(ctx, &newContainer, strings.NewReader("new backup"), newKeyring); err != nil {
		t.Fatal(err)
	}
	restored.Reset()
	if err := Open(ctx, &restored, bytes.NewReader(newContainer.Bytes()), newKeyring); err != nil {
		t.Fatalf("open new backup: %v", err)
	}
	if restored.String() != "new backup" {
		t.Fatalf("new restored = %q", restored.String())
	}
}

// Tamper + truncation are detected — backups are verified, not trusted.
func TestTamperAndTruncationDetected(t *testing.T) {
	keys := testKeys(t)
	ctx := context.Background()
	var sealed bytes.Buffer
	if err := Seal(ctx, &sealed, strings.NewReader(strings.Repeat("x", 5000)), keys); err != nil {
		t.Fatal(err)
	}
	good := sealed.Bytes()

	// Flip a byte deep in the ciphertext body → chunk auth fails.
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-10] ^= 0xff
	if err := Open(ctx, &bytes.Buffer{}, bytes.NewReader(tampered), keys); err == nil {
		t.Fatal("tampered chunk must fail authentication")
	}

	// Drop the terminator (writer died mid-stream) → truncation reported.
	truncated := good[:len(good)-4]
	err := Open(ctx, &bytes.Buffer{}, bytes.NewReader(truncated), keys)
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated container must be reported: %v", err)
	}
}

// FUZZ-004: a crafted container header declaring a ~4 GiB wrapped-DEK (or a
// huge chunk-frame length) must fail with a bounded error BEFORE allocating
// the attacker-controlled length — no unbounded make on the restore path.
func TestOpenRejectsOversizedHeaderLengthsNoHugeAlloc(t *testing.T) {
	keys := testKeys(t)
	ctx := context.Background()

	// magic || u16(keyIDLen)=0 || u32(wrappedLen)=0xFFFFFFFF || (no body)
	var hdr []byte
	hdr = append(hdr, []byte(magic)...)
	hdr = append(hdr, 0x00, 0x00)             // keyIDLen = 0
	hdr = append(hdr, 0xFF, 0xFF, 0xFF, 0xFF) // wrappedLen ~ 4 GiB
	err := Open(ctx, &bytes.Buffer{}, bytes.NewReader(hdr), keys)
	if err == nil {
		t.Fatal("oversized wrapped-dek length must be rejected")
	}
	if !strings.Contains(err.Error(), "wrapped-dek length") || !strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("expected bounded wrapped-dek cap error, got: %v", err)
	}

	// Oversized key-id length (u16 max).
	var hdr2 []byte
	hdr2 = append(hdr2, []byte(magic)...)
	hdr2 = append(hdr2, 0xFF, 0xFF) // keyIDLen = 65535 > maxKeyID
	err = Open(ctx, &bytes.Buffer{}, bytes.NewReader(hdr2), keys)
	if err == nil || !strings.Contains(err.Error(), "key id length") {
		t.Fatalf("expected bounded key-id cap error, got: %v", err)
	}

	// Oversized chunk frame: valid header from a real seal, then a forged
	// huge frame length where the first chunk should be.
	var sealed bytes.Buffer
	if err := Seal(ctx, &sealed, strings.NewReader("payload"), keys); err != nil {
		t.Fatal(err)
	}
	good := sealed.Bytes()
	// The header is fixed-size: magic(4)+u16(2)+keyID+u32(4)+wrapped. Recover
	// the header length by re-parsing, then overwrite the first chunk frame
	// length with 0xFFFFFFFF.
	hdrLen := len(magic) + 2
	keyIDLen := int(good[len(magic)])<<8 | int(good[len(magic)+1])
	hdrLen += keyIDLen
	wrappedLen := int(good[hdrLen])<<24 | int(good[hdrLen+1])<<16 | int(good[hdrLen+2])<<8 | int(good[hdrLen+3])
	hdrLen += 4 + wrappedLen
	forged := append([]byte(nil), good[:hdrLen]...)
	forged = append(forged, 0xFF, 0xFF, 0xFF, 0xFF) // huge chunk frame length
	err = Open(ctx, &bytes.Buffer{}, bytes.NewReader(forged), keys)
	if err == nil || !strings.Contains(err.Error(), "frame length") || !strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("expected bounded chunk-frame cap error, got: %v", err)
	}
}

// FuzzBackupOpen drives Open with arbitrary container bytes: no panic, no
// unbounded allocation (bounds enforced in openHeader/Open). Mirrors the
// flow/OTLP fuzz targets.
func FuzzBackupOpen(f *testing.F) {
	kek, err := crypto.Random(crypto.KeySize)
	if err != nil {
		f.Fatal(err)
	}
	keys, err := crypto.NewStaticKeyProvider("backup-fuzz", kek)
	if err != nil {
		f.Fatal(err)
	}
	ctx := context.Background()

	// Seed: a real sealed container, plus a few hostile headers.
	var sealed bytes.Buffer
	if err := Seal(ctx, &sealed, strings.NewReader("seed payload"), keys); err == nil {
		f.Add(sealed.Bytes())
	}
	f.Add([]byte(magic))
	f.Add(append([]byte(magic), 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF))
	f.Add([]byte("not a container"))
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, data []byte) {
		// Must never panic and must never hang on a huge allocation; an
		// error return is the expected outcome for hostile input.
		_ = Open(ctx, &bytes.Buffer{}, bytes.NewReader(data), keys)
	})
}
