// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ctlplne/probectl/internal/ebpf/l7"
)

// rawChunk builds the wire form of a ring-buffer record exactly as
// bpf/sslsniff.bpf.c emits it (little-endian tls_chunk). copied is what the
// kernel put in data (post-window); orig is the true plaintext size.
func rawChunk(t *testing.T, isRead uint8, copied []byte, orig int) []byte {
	t.Helper()
	c := sslChunk{PID: 4242, TID: 4243, Conn: 0xfeed, IsRead: isRead, Len: uint32(len(copied)), OrigLen: uint32(orig)}
	copy(c.Data[:], copied)
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &c); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// EBPF-002: the decode boundary is the FIRST userspace code to see ring
// bytes, and the event it returns is already redacted — no parser, buffer,
// or forwarder downstream can ever see a body byte. This is the
// redaction-before-the-forwarder proof for the live path: decodeChunk is the
// only entry point from the ring (source_live_l7_linux.go feeds its output
// straight to the channel the agent forwards from).
func TestRedactionAtDecodeBoundaryBeforeForwarder(t *testing.T) {
	req := []byte("POST /login HTTP/1.1\r\nHost: app.example\r\nContent-Length: 27\r\n\r\npassword=hunter2&user=admin")
	ev, err := decodeChunk(rawChunk(t, 0, req, len(req)), "t1", RedactHeaders)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ev.Data.Payload, []byte("hunter2")) || bytes.Contains(ev.Data.Payload, []byte("admin")) {
		t.Fatalf("sensitive body bytes crossed the decode boundary: %q", ev.Data.Payload)
	}
	if !bytes.Contains(ev.Data.Payload, []byte("POST /login")) {
		t.Fatal("protocol metadata must survive headers mode")
	}
	if ev.TenantID != "t1" || !ev.Encrypted || ev.Source.PID != 4242 || ev.ConnID != 0xfeed {
		t.Fatalf("event context wrong: %+v", ev)
	}
	if ev.Data.Size != len(req) {
		t.Fatalf("Size must report the true plaintext size: %d != %d", ev.Data.Size, len(req))
	}

	// The redacted event still parses to call metadata at the forwarder's
	// parser (what the agent actually emits downstream).
	p := l7.NewTracker(443)
	p.OnData(ev.Data)
	calls := p.OnData(l7.DataEvent{Kind: l7.Response, Payload: []byte("HTTP/1.1 204 No Content\r\n\r\n")})
	if len(calls) != 1 || calls[0].Method != "POST" || calls[0].Resource != "/login" {
		t.Fatalf("redacted event must still parse: %+v", calls)
	}
}

// A kernel capture window means Len < OrigLen: only the windowed bytes exist
// in userspace at all, and redaction still applies within them.
func TestDecodeChunkKernelWindow(t *testing.T) {
	full := append([]byte("GET /q?token=SECRET HTTP/1.1\r\n\r\n"), bytes.Repeat([]byte("B"), 2000)...)
	window := full[:64] // what a 64-byte kernel window would have copied
	ev, err := decodeChunk(rawChunk(t, 0, window, len(full)), "t1", RedactHeaders)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Data.Payload) != 64 {
		t.Fatalf("payload must be the windowed bytes only: %d", len(ev.Data.Payload))
	}
	if ev.Data.Size != len(full) {
		t.Fatalf("true size must survive the window: %d != %d", ev.Data.Size, len(full))
	}
	if bytes.Contains(ev.Data.Payload, []byte("BBBB")) {
		t.Fatal("body bytes past the window must not exist in userspace")
	}
}

// Length-only mode: the kernel ships zero payload bytes (window 0); the
// event carries direction + true size and an empty payload. Even if payload
// bytes somehow arrived, the userspace mode zeroes them (defense in depth).
func TestDecodeChunkLengthOnly(t *testing.T) {
	ev, err := decodeChunk(rawChunk(t, 1, nil, 8192), "t1", RedactLengthOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Data.Payload) != 0 {
		t.Fatalf("length-only must carry no payload: %q", ev.Data.Payload)
	}
	if ev.Data.Kind != l7.Response || ev.Data.Size != 8192 {
		t.Fatalf("metadata must survive: %+v", ev.Data)
	}

	// Defense in depth: bytes that DO arrive under length mode are zeroed.
	leaked := []byte("should-never-be-here")
	ev, err = decodeChunk(rawChunk(t, 0, leaked, len(leaked)), "t1", RedactLengthOnly)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range ev.Data.Payload {
		if b != 0 {
			t.Fatalf("length-only byte %d not zeroed: %q", i, ev.Data.Payload)
		}
	}
}

// A Len exceeding the data array (a hostile/corrupt record) is clamped, and
// a short record errors instead of fabricating an event.
func TestDecodeChunkHostileRecords(t *testing.T) {
	raw := rawChunk(t, 0, []byte("x"), 1)
	// Corrupt Len to 0xFFFFFFFF (offset: pid4+tid4+conn8+isread1+pad3 = 20).
	binary.LittleEndian.PutUint32(raw[20:], 0xFFFFFFFF)
	ev, err := decodeChunk(raw, "t1", RedactHeaders)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Data.Payload) > 4096 {
		t.Fatalf("hostile Len must clamp to the data array: %d", len(ev.Data.Payload))
	}
	if _, err := decodeChunk(raw[:16], "t1", RedactHeaders); err == nil {
		t.Fatal("truncated record must error, not fabricate an event")
	}
}

// The kernel window derivation: length→0 (nothing transits), full→max,
// headers→configured (default 1024). The BPF map's zero default is
// length-only, so an unprogrammed kernel ships NO plaintext.
func TestKernelWindowForModes(t *testing.T) {
	if w := kernelWindowFor(RedactLengthOnly, 2048); w != 0 {
		t.Fatalf("length mode must force window 0, got %d", w)
	}
	if w := kernelWindowFor(RedactFull, 256); w != maxKernelWindow {
		t.Fatalf("full mode is the whole chunk, got %d", w)
	}
	if w := kernelWindowFor(RedactHeaders, 0); w != defaultKernelWindow {
		t.Fatalf("headers default window: got %d want %d", w, defaultKernelWindow)
	}
	if w := kernelWindowFor(RedactHeaders, 512); w != 512 {
		t.Fatalf("configured window must win: got %d", w)
	}
}
