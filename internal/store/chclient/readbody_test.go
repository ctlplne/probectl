// SPDX-License-Identifier: LicenseRef-probectl-TBD

package chclient

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// infiniteReader yields the same byte forever and COUNTS how many bytes it has
// served. It backs no buffer, so a bounded reader can be proven not to allocate
// the whole stream: if ReadResponseBody read without a limit it would never
// return on this reader. served lets us assert the limit stopped the read.
type infiniteReader struct {
	b      byte
	served int
}

func (r *infiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	r.served += len(p)
	return len(p), nil
}

// TestReadResponseBodyBounded is the RED-003a / SCALE-001 acceptance test for
// the shared transport seam: an oversized (here: effectively infinite) body is
// turned into ErrResponseTooLarge after reading at most MaxResponseBytes+1,
// NOT buffered without limit. Pre-fix (a bare io.ReadAll) this either hangs
// forever on the infinite reader or OOMs; post-fix it returns a bounded error.
func TestReadResponseBodyBounded(t *testing.T) {
	r := &infiniteReader{b: 'a'}
	body, err := ReadResponseBody(r)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversized body must return ErrResponseTooLarge, got body=%d err=%v", len(body), err)
	}
	if body != nil {
		t.Fatalf("on overflow no body is returned, got %d bytes", len(body))
	}
	// The limit actually stopped the read: at most MaxResponseBytes+1 was read
	// (allowing one buffered chunk of slack from io.ReadAll's grow strategy).
	if r.served > MaxResponseBytes+1+64<<10 {
		t.Fatalf("read was not bounded: served %d bytes for a %d-byte limit", r.served, MaxResponseBytes)
	}
}

// TestReadResponseBodyAtLimit: a body exactly at the limit is returned in full
// (the bound rejects only strictly-larger bodies, so legitimate max-size
// results still decode).
func TestReadResponseBodyAtLimit(t *testing.T) {
	body, err := ReadResponseBody(bytes.NewReader(bytes.Repeat([]byte("x"), MaxResponseBytes)))
	if err != nil {
		t.Fatalf("a body at the limit must read fine: %v", err)
	}
	if len(body) != MaxResponseBytes {
		t.Fatalf("expected %d bytes, got %d", MaxResponseBytes, len(body))
	}
}

// TestReadResponseBodyOverByOne: one byte over the limit fails closed — the
// +1 sentinel detection is exact.
func TestReadResponseBodyOverByOne(t *testing.T) {
	_, err := ReadResponseBody(strings.NewReader(strings.Repeat("y", MaxResponseBytes+1)))
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("a body one byte over the limit must fail closed, got %v", err)
	}
}

// TestReadResponseBodySmall: the common case (a small JSONEachRow result) is
// returned verbatim.
func TestReadResponseBodySmall(t *testing.T) {
	const want = `{"n":"42"}` + "\n"
	body, err := ReadResponseBody(io.NopCloser(strings.NewReader(want)))
	if err != nil {
		t.Fatalf("small body: %v", err)
	}
	if string(body) != want {
		t.Fatalf("round-trip mismatch: %q", body)
	}
}
