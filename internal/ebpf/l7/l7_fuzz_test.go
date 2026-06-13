// SPDX-License-Identifier: LicenseRef-probectl-TBD

package l7

import (
	"testing"
	"time"
)

// FUZZ-002: the L7 application-protocol parsers (HTTP/1, HTTP/2, gRPC, Kafka,
// DNS) parse the RAWEST attacker-controlled content on a PRIVILEGED host agent.
// Frame/length math is exactly where coverage-guided fuzzing finds index/slice
// panics and pathological allocations that hand-written seeds miss. These
// targets drive the public Manager.OnData (which fans out through Detect +
// parserFor + every per-protocol parser) and the raw framing scanners with
// arbitrary bytes: the only invariant is no panic and no unbounded behavior —
// the parsers are observe-only and must degrade, never crash the agent.
//
// They run as ordinary unit tests against the committed seed corpus
// (testdata/fuzz/<Target>) and as coverage-guided fuzzers under -fuzz; the
// fuzz_smoke.sh nightly drives a longer fuzztime. No kernel needed: these are
// the pure-Go decode paths.

// FuzzL7Manager drives the whole protocol-detect + parse pipeline with an
// arbitrary chunk for one connection. dstPort steers Detect; kindByte picks
// request/response; the payload is the raw bytes.
func FuzzL7Manager(f *testing.F) {
	seeds := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		[]byte("POST /a HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
		// HTTP/2 client preface + an empty SETTINGS frame.
		append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 0, 0, 0, 4, 0, 0, 0, 0, 0),
		// A Kafka length-prefixed frame (size=8) of zeros.
		{0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0},
		{},
		{0xff, 0xff, 0xff, 0xff},
	}
	for _, s := range seeds {
		f.Add(uint32(80), byte(0), s)
		f.Add(uint32(443), byte(1), s)
		f.Add(uint32(9092), byte(0), s) // kafka port
		f.Add(uint32(53), byte(0), s)   // dns port
	}

	f.Fuzz(func(t *testing.T, dstPort uint32, kindByte byte, payload []byte) {
		m := NewManager()
		kind := Request
		if kindByte&1 == 1 {
			kind = Response
		}
		// Two chunks on the same connection exercise request/response pairing
		// and the cross-chunk buffering (where length math compounds).
		d := DataEvent{Kind: kind, Time: time.Unix(0, 0), Payload: payload}
		_ = m.OnData(1, dstPort, d)
		_ = m.OnData(1, dstPort, DataEvent{Kind: Response, Time: time.Unix(0, 1), Payload: payload})
		_ = m.Close(1)
	})
}

// FuzzL7Detect targets the protocol classifier directly — it reads the first
// bytes of a request to decide HTTP/1/2/gRPC/Kafka/DNS and must never panic on
// a short/garbage head.
func FuzzL7Detect(f *testing.F) {
	f.Add(uint32(80), []byte("GET / HTTP/1.1\r\n"))
	f.Add(uint32(443), []byte("PRI * HTTP/2.0\r\n\r\n"))
	f.Add(uint32(9092), []byte{0, 0, 0, 16})
	f.Add(uint32(53), []byte{0x12, 0x34, 0x01, 0x00})
	f.Add(uint32(0), []byte{})
	f.Fuzz(func(t *testing.T, dstPort uint32, head []byte) {
		_ = Detect(head, dstPort)
	})
}

// FuzzKafkaScan targets the hand-rolled Kafka length-prefixed framing — the
// int32 size field is the classic place a crafted negative/huge length forces
// a slice-out-of-range or a giant allocation.
func FuzzKafkaScan(f *testing.F) {
	f.Add([]byte{0, 0, 0, 4, 1, 2, 3, 4})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // negative/huge size
	f.Add([]byte{0, 0, 0, 0})             // zero-length
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, buf []byte) {
		msg, rest, ok := scanKafkaMessage(buf)
		if ok {
			// A successful scan must not claim more than the input holds.
			if len(msg)+len(rest) > len(buf) {
				t.Fatalf("scanKafkaMessage over-read: msg=%d rest=%d buf=%d", len(msg), len(rest), len(buf))
			}
		}
	})
}

// FuzzHTTP1Scan targets the HTTP/1 message scanner + contentLength parser (the
// Content-Length header math drives the body-length slice).
func FuzzHTTP1Scan(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"))
	f.Add([]byte("HTTP/1.1 204 No Content\r\nContent-Length: -1\r\n\r\n"))
	f.Add([]byte("X\r\nContent-Length: 99999999999999999999\r\n\r\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, buf []byte) {
		msg, rest, ok := scanHTTP1Message(buf)
		if ok && len(msg)+len(rest) > len(buf) {
			t.Fatalf("scanHTTP1Message over-read: msg=%d rest=%d buf=%d", len(msg), len(rest), len(buf))
		}
		_ = contentLength(buf)
	})
}

// FuzzHTTP2Frame targets the HTTP/2 frame extractor — the 24-bit length prefix
// is the place a crafted frame forces an over-read.
func FuzzHTTP2Frame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0})          // empty SETTINGS
	f.Add([]byte{0xff, 0xff, 0xff, 1, 0, 0, 0, 0, 1}) // 16MB-claimed length
	f.Add([]byte{0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, buf []byte) {
		fr, rest, ok := nextFrame(buf)
		if ok {
			if len(rest) > len(buf) {
				t.Fatalf("nextFrame over-read: rest=%d buf=%d", len(rest), len(buf))
			}
			_ = headerBlock(fr)
		}
	})
}
