// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package backup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/crypto"
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

func TestRewrapMovesBackupToActiveKey(t *testing.T) {
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
	if err := Seal(ctx, &oldContainer, strings.NewReader("historic backup"), oldKeys); err != nil {
		t.Fatal(err)
	}
	keyring, err := crypto.NewStaticKeyringProvider("new", newKEK, map[string][]byte{"old": oldKEK})
	if err != nil {
		t.Fatal(err)
	}
	var rewrapped bytes.Buffer
	if err := Rewrap(ctx, &rewrapped, bytes.NewReader(oldContainer.Bytes()), keyring, keyring); err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	currentOnly, err := crypto.NewStaticKeyProvider("new", newKEK)
	if err != nil {
		t.Fatal(err)
	}
	var restored bytes.Buffer
	if err := Open(ctx, &restored, bytes.NewReader(rewrapped.Bytes()), currentOnly); err != nil {
		t.Fatalf("current-only open after rewrap: %v", err)
	}
	if restored.String() != "historic backup" {
		t.Fatalf("restored = %q", restored.String())
	}
	if err := Open(ctx, &bytes.Buffer{}, bytes.NewReader(oldContainer.Bytes()), currentOnly); err == nil {
		t.Fatal("pre-rewrap old backup must not open after old opener removal")
	}
}

func TestStreamingBackupDEKsAreZeroized(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve backup test source path")
	}
	srcBytes, err := os.ReadFile(filepath.Join(filepath.Dir(file), "backup.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(srcBytes)

	for _, fn := range []string{"Seal", "Open"} {
		block, ok := functionSource(src, fn)
		if !ok {
			t.Fatalf("backup.%s source block not found", fn)
		}
		if !strings.Contains(block, "defer crypto.Zeroize(dek)") {
			t.Fatalf("backup.%s must zeroize the streaming backup DEK on every return path", fn)
		}
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
// unbounded allocation (bounds enforced in openHeader/Open), and — PLAT-14 —
// Open never ACCEPTS a mutated container as valid-but-different. The fuzzer
// holds the KEK but not a way to forge AES-256-GCM tags or the DEK-bound MAC
// chain, so the only input that opens successfully is one that reproduces the
// exact original plaintext; a successful open whose output differs is a
// forgery the trailer/MAC must prevent. Mirrors the flow/OTLP fuzz targets.
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

	original := []byte("TENANT-SECRET seed payload for the backup fuzz target\n" +
		strings.Repeat("row data more data\n", 128))

	// Seed: a real sealed container, plus a few hostile headers.
	var sealed bytes.Buffer
	if err := Seal(ctx, &sealed, bytes.NewReader(original), keys); err == nil {
		f.Add(sealed.Bytes())
	}
	f.Add([]byte(magic))
	f.Add(append([]byte(magic), 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF))
	f.Add([]byte("not a container"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic and must never hang on a huge allocation; an error
		// return is the expected outcome for hostile input.
		var out bytes.Buffer
		if err := Open(ctx, &out, bytes.NewReader(data), keys); err == nil {
			// Open accepted the container. It MUST be the genuine backup: a
			// mutation that changed the authenticated content and still opened
			// would be silently-accepted tampering (PLAT-14).
			if !bytes.Equal(out.Bytes(), original) {
				t.Fatalf("Open accepted a mutated container whose output differs from the original (%d bytes) — tamper accepted", out.Len())
			}
		}
	})
}

// TestBackupContainerTamperEvidencePLAT14 drives the real write-then-open path
// and asserts the container is tamper-evident end to end: a genuine backup
// round-trips, while truncation (at or between frame boundaries), frame
// reordering, header substitution, and an appended tail all fail to open.
// Before the PBK2 authenticated trailer, a cut-at-a-frame-boundary container
// with a forged end-of-chunks marker opened as a valid-but-incomplete backup.
func TestBackupContainerTamperEvidencePLAT14(t *testing.T) {
	keys := testKeys(t)
	ctx := context.Background()

	// A multi-chunk dump so there is a real interior frame boundary to cut at.
	var plain bytes.Buffer
	plain.WriteString("PGDMP fake header\n")
	for i := 0; i < 70000; i++ { // comfortably > chunkSize → ≥2 data frames
		plain.WriteString("row data TENANT-SECRET more data\n")
	}
	original := plain.Bytes()

	seal := func(t *testing.T) []byte {
		t.Helper()
		var b bytes.Buffer
		if err := Seal(ctx, &b, bytes.NewReader(original), keys); err != nil {
			t.Fatalf("seal: %v", err)
		}
		return b.Bytes()
	}

	opens := func(container []byte) error {
		return Open(ctx, &bytes.Buffer{}, bytes.NewReader(container), keys)
	}

	t.Run("genuine backup round-trips", func(t *testing.T) {
		var restored bytes.Buffer
		if err := Open(ctx, &restored, bytes.NewReader(seal(t)), keys); err != nil {
			t.Fatalf("genuine backup must open: %v", err)
		}
		if !bytes.Equal(restored.Bytes(), original) {
			t.Fatalf("restore mismatch: %d vs %d bytes", restored.Len(), len(original))
		}
	})

	// Truncation at a frame boundary with a FORGED end-of-chunks marker — the
	// PLAT-14 case. Drop the last data frame and the real trailer, keep a
	// forged zero-length marker so the stream looks "cleanly" ended.
	t.Run("truncation at frame boundary (forged marker) fails", func(t *testing.T) {
		header, frames, _ := parsePBK(t, seal(t))
		if len(frames) < 2 {
			t.Fatalf("need ≥2 data frames to cut at an interior boundary, got %d", len(frames))
		}
		var cut bytes.Buffer
		cut.Write(header)
		for _, fr := range frames[:len(frames)-1] { // drop the last data frame
			cut.Write(fr)
		}
		cut.Write([]byte{0, 0, 0, 0}) // forged end-of-chunks marker, no trailer
		if err := opens(cut.Bytes()); err == nil {
			t.Fatal("PLAT-14: truncation at a frame boundary with a forged marker must fail to open")
		}
	})

	t.Run("truncation mid-frame fails", func(t *testing.T) {
		good := seal(t)
		header, frames, _ := parsePBK(t, good)
		// Keep the header and a partial first data frame (chop its last byte).
		mid := append([]byte(nil), header...)
		mid = append(mid, frames[0][:len(frames[0])-1]...)
		if err := opens(mid); err == nil {
			t.Fatal("a mid-frame truncation must fail to open")
		}
	})

	t.Run("frame reordering fails", func(t *testing.T) {
		header, frames, tail := parsePBK(t, seal(t))
		if len(frames) < 2 {
			t.Fatalf("need ≥2 data frames to reorder, got %d", len(frames))
		}
		var reordered bytes.Buffer
		reordered.Write(header)
		reordered.Write(frames[1]) // swap the first two data frames
		reordered.Write(frames[0])
		for _, fr := range frames[2:] {
			reordered.Write(fr)
		}
		reordered.Write(tail)
		if err := opens(reordered.Bytes()); err == nil {
			t.Fatal("reordered frames must fail to open")
		}
	})

	t.Run("header substitution fails", func(t *testing.T) {
		// A second genuine backup sealed under the SAME keys: its header wraps a
		// different fresh DEK. Splicing it onto this body must not validate.
		otherHeader, _, _ := parsePBK(t, seal(t))
		_, frames, tail := parsePBK(t, seal(t))
		var spliced bytes.Buffer
		spliced.Write(otherHeader)
		for _, fr := range frames {
			spliced.Write(fr)
		}
		spliced.Write(tail)
		if err := opens(spliced.Bytes()); err == nil {
			t.Fatal("a substituted header must fail to open")
		}
	})

	t.Run("appended tail fails", func(t *testing.T) {
		appended := append(seal(t), []byte("extra trailing bytes")...)
		if err := opens(appended); err == nil {
			t.Fatal("data appended after the authenticated trailer must fail to open")
		}
	})

	t.Run("legacy PBK1 container is rejected", func(t *testing.T) {
		good := seal(t)
		legacy := append([]byte(nil), good...)
		copy(legacy, []byte("PBK1"))
		err := opens(legacy)
		if err == nil || !strings.Contains(err.Error(), "legacy") {
			t.Fatalf("a downgraded/legacy PBK1 magic must be rejected loudly, got: %v", err)
		}
	})
}

// parsePBK splits a PBK2 container into its header, ordered data-frame byte
// slices (each the full uint32-length-prefixed frame), and the tail (the
// zero-length end-of-chunks marker plus the sealed trailer frame).
func parsePBK(t *testing.T, c []byte) (header []byte, frames [][]byte, tail []byte) {
	t.Helper()
	off := len(magic)
	keyIDLen := int(c[off])<<8 | int(c[off+1])
	off += 2 + keyIDLen
	wrappedLen := int(c[off])<<24 | int(c[off+1])<<16 | int(c[off+2])<<8 | int(c[off+3])
	off += 4 + wrappedLen
	header = append([]byte(nil), c[:off]...)
	for {
		n := int(c[off])<<24 | int(c[off+1])<<16 | int(c[off+2])<<8 | int(c[off+3])
		if n == 0 {
			break // end-of-chunks marker
		}
		frames = append(frames, append([]byte(nil), c[off:off+4+n]...))
		off += 4 + n
	}
	tail = append([]byte(nil), c[off:]...) // marker + sealed trailer frame
	return header, frames, tail
}

func functionSource(src, name string) (string, bool) {
	start := strings.Index(src, "func "+name+"(")
	if start < 0 {
		return "", false
	}
	depth := 0
	seenBody := false
	for i := start; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
			seenBody = true
		case '}':
			if !seenBody {
				continue
			}
			depth--
			if depth == 0 {
				return src[start : i+1], true
			}
		}
	}
	return "", false
}
