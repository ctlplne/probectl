// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package wire is the ONE way probectl's decoders consume untrusted network
// bytes (Foundation-Loop S-9e6855ec).
//
// Before this package, five bounds idioms coexisted across the protocol
// decoders — a sticky-error cursor for sFlow, hand-rolled offset arithmetic
// for NetFlow v9/IPFIX, one upfront length check then unchecked fixed-offset
// slicing for NetFlow v5, two-pass count-then-decode for BMP framing — none of
// them shared, so every new protocol invented a sixth. A panic-recover on the
// ingest loop is a net, not a floor.
//
// Reader is the floor. Every read is bounds-checked before it happens; the
// FIRST overrun latches an error and every later read returns a zero value, so
// a decoder may parse a whole message and check Err() once at the end without
// ever indexing a slice itself. Sub gives a length-delimited view so nested
// framing (flowsets, records, TLVs) inherits bounds for free: a malformed
// inner length can consume at most its own frame.
//
// Reads never allocate: Bytes returns a sub-slice of the caller's buffer, and
// the fixed-size accessors return arrays by value. Decoders on the hot ingest
// path (the flow plane's per-datagram budget is a CI tripwire) pay nothing for
// the safety.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrTruncated is the sentinel every bounds failure wraps, so callers can
// distinguish "the sender sent us garbage" from a semantic decode error.
var ErrTruncated = errors.New("wire: truncated input")

// Reader is a bounds-checked big-endian cursor over untrusted bytes. The zero
// value is not usable; build one with New or Sub.
type Reader struct {
	b   []byte
	off int
	err error
}

// New wraps b. The reader never retains anything beyond b itself.
func New(b []byte) *Reader { return &Reader{b: b} }

// Err reports the first bounds failure, or nil when every read succeeded.
func (r *Reader) Err() error { return r.err }

// Remaining is how many bytes are left unread (0 once an error has latched).
func (r *Reader) Remaining() int {
	if r.err != nil {
		return 0
	}
	return len(r.b) - r.off
}

// Offset is the current read position, for diagnostics.
func (r *Reader) Offset() int { return r.off }

// Empty reports whether the reader is exhausted or failed — the loop condition
// for "consume records until the frame runs out".
func (r *Reader) Empty() bool { return r.Remaining() == 0 }

// take advances by n after checking bounds, returning the consumed slice.
// A failed reader (or an overrun) returns nil and latches the error.
func (r *Reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 {
		r.failf("negative read length %d", n)
		return nil
	}
	if r.off+n > len(r.b) {
		r.failf("read of %d bytes at offset %d exceeds %d-byte input", n, r.off, len(r.b))
		return nil
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v
}

func (r *Reader) failf(format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf("%w: %s", ErrTruncated, fmt.Sprintf(format, args...))
	}
}

// U8 reads one byte.
func (r *Reader) U8() uint8 {
	v := r.take(1)
	if v == nil {
		return 0
	}
	return v[0]
}

// U16 reads a big-endian uint16.
func (r *Reader) U16() uint16 {
	v := r.take(2)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint16(v)
}

// U32 reads a big-endian uint32.
func (r *Reader) U32() uint32 {
	v := r.take(4)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v)
}

// Bytes reads n bytes as a sub-slice of the underlying buffer (no copy). The
// result aliases the caller's input, exactly like a hand-written slice would,
// but can never be out of range.
func (r *Reader) Bytes(n int) []byte { return r.take(n) }

// Array4 reads 4 bytes by value — an IPv4 address without allocating.
func (r *Reader) Array4() [4]byte {
	v := r.take(4)
	if v == nil {
		return [4]byte{}
	}
	return [4]byte(v)
}

// BytesAligned reads n bytes and then skips the padding that XDR-style
// encodings append to round an opaque field up to a multiple of align (sFlow's
// 4-byte opaque padding). The pad is computed from the FIELD LENGTH, matching
// the encoding rule; padding absent at the very end of a frame is tolerated,
// so a truncated final field does not latch an error the sender did not cause.
func (r *Reader) BytesAligned(n, align int) []byte {
	v := r.take(n)
	if v == nil || align <= 1 {
		return v
	}
	pad := (align - n%align) % align
	if pad > 0 && r.off+pad <= len(r.b) {
		r.off += pad
	}
	return v
}

// Skip advances past n bytes.
func (r *Reader) Skip(n int) { r.take(n) }

// Sub returns a reader over the next n bytes and advances this one past them.
// Nested framing inherits bounds: whatever the inner frame claims, it cannot
// read beyond the length its parent granted. A sub-reader that overruns
// latches its own error without corrupting the parent's position.
func (r *Reader) Sub(n int) *Reader {
	v := r.take(n)
	if v == nil {
		// Hand back a failed reader so callers can keep parsing structurally
		// without nil checks; Err() on either reader reports the truncation.
		failed := &Reader{}
		failed.failf("sub-reader of %d bytes is not available", n)
		return failed
	}
	return &Reader{b: v}
}
