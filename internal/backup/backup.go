// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package backup is probectl's at-rest backup encryption (OPS-002): a
// streaming envelope-encrypted container so a pg_dump / ClickHouse BACKUP
// never lands on disk in plaintext. It reuses the Sprint 8 at-rest key
// management (internal/crypto envelope: a fresh DEK per backup, wrapped by
// the deployment KEK) — crypto goes through internal/crypto only (guardrail
// 3, docs/guardrails.md G7-3).
//
// Format (.pbk container, version "PBK2"), chunked so an arbitrarily large
// dump streams without buffering in memory:
//
//	magic "PBK2" || uint16(len keyID) || keyID
//	     || uint32(len wrappedDEK) || wrappedDEK
//	     || repeated: uint32(len chunkCiphertext) || chunkCiphertext
//	     || uint32(0)                       # end-of-chunks marker
//	     || uint32(len trailer) || trailer  # sealed, authenticated trailer
//
// Each chunk is sealed with AES-256-GCM under the DEK, with the chunk INDEX
// as additional data — so a tampered or in-place-reordered chunk fails to
// open. That alone did NOT bind the stream as a whole: the end-of-chunks
// marker was unauthenticated, so a container could be cut at a chunk boundary
// (dropping trailing chunks), have a forged marker appended, or carry a
// substituted header, and still "open" as a valid-but-incomplete backup
// (PLAT-14). PBK2 closes that: a running MAC chains the header and every
// ordered frame, and a final sealed trailer binds the exact frame count and
// that chain. On open the trailer is mandatory and verified, so ANY truncation
// (at or between frame boundaries), frame reordering, header substitution, or
// appended tail fails closed — backups are verified, not trusted (G7-6).
//
// PBK2 is a deliberate on-disk format bump: legacy "PBK1" containers predate
// the authenticated trailer and cannot be made truncation-evident after the
// fact, so Open rejects them with an actionable error rather than silently
// accepting an unverifiable backup (see docs/ops/backup-restore.md).
package backup

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/ctlplne/probectl/internal/crypto"
)

const (
	magic       = "PBK2"
	legacyMagic = "PBK1"  // pre-trailer container; no longer accepted on open
	chunkSize   = 1 << 20 // 1 MiB plaintext per sealed chunk

	// maxWrappedDEK bounds the wrapped-DEK header length we will allocate
	// from an untrusted/semi-trusted container before reading it. A wrapped
	// DEK is a few hundred bytes; 64 KiB is generous and prevents a crafted
	// u32 length (up to ~4 GiB) from forcing an unbounded allocation
	// (FUZZ-004 allocation-DoS on the restore path).
	maxWrappedDEK = 64 << 10 // 64 KiB
	// maxKeyID bounds the key-id header length (a u16, so already <=64 KiB,
	// but we cap tighter to a sane identifier size).
	maxKeyID = 4 << 10 // 4 KiB
	// maxChunkCiphertext bounds a single sealed-chunk frame: plaintext is
	// chunkSize, plus AEAD nonce+tag overhead; 1 MiB slack is ample. Caps
	// the per-frame allocation in Open so a crafted frame length cannot
	// force a multi-GiB make.
	maxChunkCiphertext = chunkSize + (1 << 20) // 2 MiB
	// maxTrailer bounds the sealed-trailer frame. The trailer plaintext is a
	// single uint64 frame count; sealed it is ~36 bytes. 1 KiB caps the
	// allocation without constraining a future trailer field.
	maxTrailer = 1 << 10 // 1 KiB
)

// Domain-separation labels keep the backup MAC chain and trailer AEAD distinct
// from any other use of the DEK, and bind this container version.
var (
	chainSeedLabel = []byte("probectl.backup.pbk2.chain-seed")
	chainStepLabel = []byte("probectl.backup.pbk2.chain-step")
	trailerLabel   = []byte("probectl.backup.pbk2.trailer")
	macSubkeyLabel = []byte("probectl.backup.pbk2.mac-subkey")
)

// KeyProvider wraps/unwraps the data key (the deployment KEK side). The
// crypto.KeyProvider from internal/crypto satisfies it; the CLI builds one
// from the envelope key.
type KeyProvider = crypto.KeyProvider

// Seal streams src → dst, envelope-encrypted. A single fresh DEK is minted
// for the whole backup and wrapped by keys; each chunk is independently
// sealed, and a final authenticated trailer binds the ordered stream. dst
// receives the .pbk container.
func Seal(ctx context.Context, dst io.Writer, src io.Reader, keys KeyProvider) error {
	// One fresh DEK for the whole backup, wrapped by the KEK in the header;
	// each chunk is then sealed under that DEK with its index as AAD, and a
	// DEK-bound running MAC chains the header + every frame for the trailer.
	hdr, dek, err := sealHeader(ctx, keys)
	if err != nil {
		return err
	}
	defer crypto.Zeroize(dek)
	macKey := deriveChainKey(dek)
	defer crypto.Zeroize(macKey)
	if _, err := dst.Write(hdr); err != nil {
		return fmt.Errorf("backup: write header: %w", err)
	}
	chain := seedChain(macKey, hdr)

	buf := make([]byte, chunkSize)
	var index uint64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, rerr := io.ReadFull(src, buf)
		if n > 0 {
			ct, err := crypto.Encrypt(dek, buf[:n], chunkAAD(index))
			if err != nil {
				return fmt.Errorf("backup: seal chunk %d: %w", index, err)
			}
			if err := writeFrame(dst, ct); err != nil {
				return err
			}
			chain = advanceChain(macKey, chain, index, len(ct))
			index++
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("backup: read input: %w", rerr)
		}
	}
	// Zero-length marker ends the chunk stream; the sealed trailer follows and
	// authenticates the whole ordered container.
	if err := binary.Write(dst, binary.BigEndian, uint32(0)); err != nil {
		return fmt.Errorf("backup: write end-of-chunks marker: %w", err)
	}
	return sealTrailer(dst, dek, chain, index)
}

// Open streams a .pbk container src → dst, decrypted. A truncated file (at or
// between frame boundaries), a tampered or reordered chunk, a substituted
// header, or an appended tail all fail — the final sealed trailer is mandatory
// and binds the whole ordered stream. Backups are verified, not trusted.
func Open(ctx context.Context, dst io.Writer, src io.Reader, keys KeyProvider) error {
	dek, hdr, err := openHeader(ctx, src, keys)
	if err != nil {
		return err
	}
	defer crypto.Zeroize(dek)
	macKey := deriveChainKey(dek)
	defer crypto.Zeroize(macKey)
	chain := seedChain(macKey, hdr)

	var index uint64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var n uint32
		if err := binary.Read(src, binary.BigEndian, &n); err != nil {
			if errors.Is(err, io.EOF) {
				return errors.New("backup: truncated container (missing end-of-chunks marker) — incomplete or corrupt backup")
			}
			return fmt.Errorf("backup: read frame length: %w", err)
		}
		if n == 0 {
			// End of chunks: the trailer is mandatory and verifies the stream.
			return openTrailer(src, dek, chain, index)
		}
		// Bound the per-frame allocation: a sealed chunk is at most chunkSize
		// plus AEAD overhead, so a crafted frame length cannot force a
		// multi-GiB make (FUZZ-004 allocation-DoS).
		if n > maxChunkCiphertext {
			return fmt.Errorf("backup: chunk %d frame length %d exceeds cap %d (corrupt/hostile container)", index, n, maxChunkCiphertext)
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(src, ct); err != nil {
			return fmt.Errorf("backup: short read on chunk %d (corrupt): %w", index, err)
		}
		pt, err := crypto.Decrypt(dek, ct, chunkAAD(index))
		if err != nil {
			return fmt.Errorf("backup: chunk %d failed authentication (tampered/reordered): %w", index, err)
		}
		if _, err := dst.Write(pt); err != nil {
			return fmt.Errorf("backup: write output: %w", err)
		}
		chain = advanceChain(macKey, chain, index, int(n))
		index++
	}
}

// Rewrap streams an existing encrypted backup through Open and Seal so the
// output container is wrapped by the current active KEK. Plaintext exists only
// in memory between the two pipes and is never written as an intermediate file.
func Rewrap(ctx context.Context, dst io.Writer, src io.Reader, openKeys, sealKeys KeyProvider) error {
	pr, pw := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		err := Open(ctx, pw, src, openKeys)
		if err != nil {
			_ = pw.CloseWithError(err)
		} else {
			_ = pw.Close()
		}
		errc <- err
	}()
	sealErr := Seal(ctx, dst, pr, sealKeys)
	openErr := <-errc
	if sealErr != nil {
		return sealErr
	}
	return openErr
}

// --- header (carries the wrapped DEK) ---

// sealHeader mints a DEK, wraps it under the KEK, and renders the container
// header. The raw DEK is returned for chunk AEAD.
func sealHeader(ctx context.Context, keys KeyProvider) (hdr, dek []byte, err error) {
	dek, err = crypto.Random(crypto.KeySize)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			crypto.Zeroize(dek)
		}
	}()
	wrapped, err := keys.WrapKey(ctx, dek)
	if err != nil {
		return nil, nil, fmt.Errorf("backup: wrap dek: %w", err)
	}
	keyID := keys.KeyID()
	var b []byte
	b = append(b, magic...)
	b = appendU16(b, uint16(len(keyID)))
	b = append(b, keyID...)
	b = appendU32(b, uint32(len(wrapped)))
	b = append(b, wrapped...)
	return b, dek, nil
}

// openHeader parses the header, unwraps the DEK, and returns the exact header
// bytes so the caller can re-seed the running MAC chain over them (a
// substituted header then fails the trailer check).
func openHeader(ctx context.Context, src io.Reader, keys KeyProvider) (dek, hdr []byte, err error) {
	m := make([]byte, len(magic))
	if _, err := io.ReadFull(src, m); err != nil {
		return nil, nil, fmt.Errorf("backup: read magic: %w", err)
	}
	if string(m) == legacyMagic {
		return nil, nil, fmt.Errorf("backup: legacy %q container is not truncation-authenticated and is no longer accepted — re-seal with this version (see docs/ops/backup-restore.md)", legacyMagic)
	}
	if string(m) != magic {
		return nil, nil, fmt.Errorf("backup: bad magic %q (not a probectl %s backup container)", m, magic)
	}
	hdr = append(hdr, m...)

	keyIDLen, err := readU16(src)
	if err != nil {
		return nil, nil, err
	}
	if int(keyIDLen) > maxKeyID {
		return nil, nil, fmt.Errorf("backup: key id length %d exceeds cap %d (corrupt/hostile header)", keyIDLen, maxKeyID)
	}
	keyID := make([]byte, keyIDLen)
	if _, err := io.ReadFull(src, keyID); err != nil {
		return nil, nil, fmt.Errorf("backup: read key id: %w", err)
	}
	hdr = appendU16(hdr, keyIDLen)
	hdr = append(hdr, keyID...)

	wrappedLen, err := readU32(src)
	if err != nil {
		return nil, nil, err
	}
	// Bound the allocation before reading: a crafted u32 length (up to
	// ~4 GiB) must not force an unbounded make on the restore path
	// (FUZZ-004). A wrapped DEK is a few hundred bytes.
	if wrappedLen > maxWrappedDEK {
		return nil, nil, fmt.Errorf("backup: wrapped-dek length %d exceeds cap %d (corrupt/hostile header)", wrappedLen, maxWrappedDEK)
	}
	wrapped := make([]byte, wrappedLen)
	if _, err := io.ReadFull(src, wrapped); err != nil {
		return nil, nil, fmt.Errorf("backup: read wrapped dek: %w", err)
	}
	hdr = appendU32(hdr, wrappedLen)
	hdr = append(hdr, wrapped...)

	dek, err = keys.UnwrapKey(ctx, string(keyID), wrapped)
	if err != nil {
		return nil, nil, fmt.Errorf("backup: unwrap dek (wrong KEK for key id %q?): %w", keyID, err)
	}
	return dek, hdr, nil
}

// --- authenticated trailer + running MAC chain ---

// deriveChainKey derives the DEK-bound MAC key for the frame chain, so the
// chain never keys HMAC directly with the GCM key (domain separation). The
// returned key is 32 bytes (HMAC-SHA256 output) and must be zeroized.
func deriveChainKey(dek []byte) []byte { return crypto.Sign(dek, macSubkeyLabel) }

// seedChain starts the running frame MAC, binding the entire header (magic,
// key id, wrapped DEK) — a substituted header diverges the chain and fails
// the trailer check.
func seedChain(macKey, hdr []byte) []byte {
	seed := make([]byte, 0, len(chainSeedLabel)+len(hdr))
	seed = append(seed, chainSeedLabel...)
	seed = append(seed, hdr...)
	return crypto.Sign(macKey, seed)
}

// advanceChain folds frame i (its ordinal and on-wire ciphertext length) into
// the running MAC, so a dropped, added, or reordered frame diverges the chain.
func advanceChain(macKey, chain []byte, index uint64, ctLen int) []byte {
	step := make([]byte, 0, len(chainStepLabel)+len(chain)+12)
	step = append(step, chainStepLabel...)
	step = append(step, chain...)
	step = appendU64(step, index)
	step = appendU32(step, uint32(ctLen))
	return crypto.Sign(macKey, step)
}

// trailerAAD binds the sealed trailer to the running chain (header + every
// ordered frame), so the trailer authenticates the whole container.
func trailerAAD(chain []byte) []byte {
	aad := make([]byte, 0, len(trailerLabel)+len(chain))
	aad = append(aad, trailerLabel...)
	aad = append(aad, chain...)
	return aad
}

// sealTrailer writes the final authenticated trailer: the frame count sealed
// under the DEK, bound to the running chain. Its presence and authenticity are
// mandatory on open.
func sealTrailer(dst io.Writer, dek, chain []byte, frameCount uint64) error {
	plain := appendU64(nil, frameCount)
	ct, err := crypto.Encrypt(dek, plain, trailerAAD(chain))
	if err != nil {
		return fmt.Errorf("backup: seal trailer: %w", err)
	}
	return writeFrame(dst, ct)
}

// openTrailer reads and verifies the mandatory trailer, then requires EOF. Any
// missing/short/mismatching trailer, a frame-count that disagrees with the
// chunks actually read, or trailing bytes after the trailer fails closed.
func openTrailer(src io.Reader, dek, chain []byte, frameCount uint64) error {
	n, err := readU32(src)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("backup: truncated container (missing authenticated trailer) — incomplete or tampered backup")
		}
		return fmt.Errorf("backup: read trailer length: %w", err)
	}
	if n == 0 || n > maxTrailer {
		return fmt.Errorf("backup: trailer frame length %d invalid (corrupt/hostile container)", n)
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(src, ct); err != nil {
		return fmt.Errorf("backup: short read on trailer (truncated/corrupt): %w", err)
	}
	plain, err := crypto.Decrypt(dek, ct, trailerAAD(chain))
	if err != nil {
		return fmt.Errorf("backup: trailer failed authentication (truncated/reordered/substituted header): %w", err)
	}
	if len(plain) != 8 {
		return fmt.Errorf("backup: trailer payload length %d invalid", len(plain))
	}
	if got := binary.BigEndian.Uint64(plain); got != frameCount {
		return fmt.Errorf("backup: trailer frame count %d != %d chunks read (truncated/tampered)", got, frameCount)
	}
	// No bytes may follow the authenticated trailer.
	var probe [1]byte
	if _, err := io.ReadFull(src, probe[:]); err == nil {
		return errors.New("backup: trailing data after authenticated trailer (tampered/appended)")
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("backup: read after trailer: %w", err)
	}
	return nil
}

func chunkAAD(index uint64) []byte {
	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, index)
	return aad
}

func writeFrame(w io.Writer, payload []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(payload))); err != nil {
		return fmt.Errorf("backup: write frame length: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("backup: write frame: %w", err)
	}
	return nil
}

func appendU16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }
func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
func appendU64(b []byte, v uint64) []byte {
	return append(b,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
func readU16(r io.Reader) (uint16, error) {
	var v uint16
	err := binary.Read(r, binary.BigEndian, &v)
	return v, err
}
func readU32(r io.Reader) (uint32, error) {
	var v uint32
	err := binary.Read(r, binary.BigEndian, &v)
	return v, err
}
