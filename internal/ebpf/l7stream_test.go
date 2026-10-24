// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"bytes"
	"strings"
	"testing"
)

const bodySecret = "account=private-body-bytes&note=never-retained"

func zeroed(p []byte) bool { return len(bytes.Trim(p, "\x00")) == 0 }

// DPR-340: under "headers" redaction a body-only continuation chunk was judged
// alone, so it kept its first 128 bytes (or everything up to a "\r\n\r\n"
// inside the body). Through the live decode path with the source's stream
// history, the headers chunk keeps its headers and the body chunk that follows
// is zeroed whole.
func TestDecodeBoundaryZeroesABodyOnlyContinuationChunk(t *testing.T) {
	streams := newStreamRedactor()
	headers := "POST /pay HTTP/1.1\r\nHost: shop\r\nContent-Length: 4096\r\n\r\n"
	first, err := decodeChunkWithPolicy(rawChunk(t, 0, []byte(headers), len(headers)), "t1", RedactHeaders, headerValuePolicy{}, streams)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(first.Data.Payload), "POST /pay HTTP/1.1\r\nHost: shop") {
		t.Fatalf("the headers chunk lost its headers: %q", first.Data.Payload)
	}
	for _, body := range []string{
		bodySecret + strings.Repeat("x", 300),              // more than the 128-byte prefix
		bodySecret + "\r\n\r\n" + strings.Repeat("y", 200), // a header terminator inside the body
	} {
		next, err := decodeChunkWithPolicy(rawChunk(t, 0, []byte(body), len(body)), "t1", RedactHeaders, headerValuePolicy{}, streams)
		if err != nil {
			t.Fatal(err)
		}
		if !zeroed(next.Data.Payload) || next.Data.Size != len(body) {
			t.Fatalf("a body-only continuation chunk kept plaintext %q (size %d)", bytes.Trim(next.Data.Payload, "\x00"), next.Data.Size)
		}
	}
}

func TestStreamRedactorRules(t *testing.T) {
	key := streamKey{pid: 1, conn: 2}
	other := streamKey{pid: 1, conn: 2, read: true}
	run := func(r *streamRedactor, k streamKey, s string) string {
		return string(bytes.TrimRight(r.redact(k, []byte(s), RedactHeaders, headerValuePolicy{}), "\x00"))
	}

	t.Run("headers split across chunks keep both parts, then the body is zeroed", func(t *testing.T) {
		r := newStreamRedactor()
		if got := run(r, key, "GET /a HTTP/1.1\r\nHost: a"); got != "GET /a HTTP/1.1\r\nHost: a" {
			t.Fatalf("first header chunk = %q", got)
		}
		if got := run(r, key, "\r\nAccept: */*\r\n\r\n"); got != "\r\nAccept: */*\r\n\r\n" {
			t.Fatalf("header continuation = %q", got)
		}
		if got := run(r, key, bodySecret); got != "" {
			t.Fatalf("body after the split headers kept %q", got)
		}
	})
	t.Run("the next message on the same stream keeps its headers", func(t *testing.T) {
		r := newStreamRedactor()
		run(r, key, "POST /a HTTP/1.1\r\nContent-Length: 40\r\n\r\n")
		run(r, key, bodySecret)
		if got := run(r, key, "GET /b HTTP/1.1\r\n\r\n"); got != "GET /b HTTP/1.1\r\n\r\n" {
			t.Fatalf("a pipelined request lost its headers: %q", got)
		}
	})
	t.Run("each direction is its own stream", func(t *testing.T) {
		r := newStreamRedactor()
		run(r, key, "POST /a HTTP/1.1\r\n\r\n")
		if got := run(r, other, "HTTP/1.1 200 OK\r\n\r\n"); got != "HTTP/1.1 200 OK\r\n\r\n" {
			t.Fatalf("the response stream inherited the request stream's body state: %q", got)
		}
	})
	t.Run("a non-HTTP stream keeps the per-chunk rule", func(t *testing.T) {
		r := newStreamRedactor()
		ping := "*1\r\n$4\r\nPING\r\n"
		for range 3 {
			if got := run(r, key, ping); got != ping {
				t.Fatalf("a Redis command was changed: %q", got)
			}
		}
	})
	t.Run("full and length-only modes ignore stream state", func(t *testing.T) {
		r := newStreamRedactor()
		run(r, key, "POST /a HTTP/1.1\r\n\r\n")
		if got := string(r.redact(key, []byte(bodySecret), RedactFull, headerValuePolicy{})); got != bodySecret {
			t.Fatalf("full mode changed the body: %q", got)
		}
	})
	t.Run("the state is bounded and a forgotten stream falls back to the per-chunk rule", func(t *testing.T) {
		r := newStreamRedactor()
		r.max = 2
		run(r, key, "POST /a HTTP/1.1\r\n\r\n")
		run(r, streamKey{conn: 10}, "GET / HTTP/1.1\r\n")
		run(r, streamKey{conn: 11}, "GET / HTTP/1.1\r\n")
		if len(r.state) != 2 || len(r.order) != 2 {
			t.Fatalf("tracked %d streams (%d ordered), want the bound 2", len(r.state), len(r.order))
		}
		long := bodySecret + strings.Repeat("z", 300)
		if got := run(r, key, long); got != long[:redactKeepPrefix] {
			t.Fatalf("an evicted stream did not fall back to the per-chunk rule: %q", got)
		}
	})
}
