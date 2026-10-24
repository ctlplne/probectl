// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"bytes"
	"sync"
)

// streamRedactor carries the one fact the per-chunk boundary cannot see on its
// own (DPR-340): whether an HTTP/1 message's headers have already ended on this
// stream. redactPayloadWithPolicy judges each chunk alone, so under "headers"
// redaction a body-only continuation chunk was treated as headers and kept its
// first redactKeepPrefix bytes, or everything up to a "\r\n\r\n" inside the
// body. With the stream's state, a chunk that continues a message whose headers
// ended is body and is zeroed whole.
//
// A stream is one direction of one connection of one process. Only streams that
// have shown an HTTP/1 message start are tracked: other protocols keep the
// per-chunk rule, which protocol detection relies on. State is bounded; a
// forgotten stream falls back to the per-chunk rule, never to keeping more.
type streamRedactor struct {
	mu    sync.Mutex
	state map[streamKey]streamState
	order []streamKey // insertion order, for the bound
	max   int
}

type streamKey struct {
	pid  uint32
	conn uint64
	read bool
}

type streamState uint8

const (
	streamInHeaders streamState = iota + 1 // an HTTP/1 message started; its headers have not ended
	streamInBody                           // its headers ended: what follows is body until the next message
)

// maxRedactorStreams bounds the tracked streams (one entry per direction of a
// live HTTP/1 connection).
const maxRedactorStreams = 8192

func newStreamRedactor() *streamRedactor {
	return &streamRedactor{state: map[streamKey]streamState{}, max: maxRedactorStreams}
}

// http1Methods are the request-line methods that open an HTTP/1 request.
var http1Methods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "), []byte("HEAD "),
	[]byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "), []byte("TRACE "),
}

// startsHTTP1Message reports whether p begins an HTTP/1 request or response.
func startsHTTP1Message(p []byte) bool {
	if bytes.HasPrefix(p, []byte("HTTP/1.")) {
		return true
	}
	for _, m := range http1Methods {
		if bytes.HasPrefix(p, m) {
			return true
		}
	}
	return false
}

// redact applies the capture boundary to p (the caller's private copy) with
// the stream's history, and returns it. Modes other than "headers" are
// stream-independent and go straight to redactPayloadWithPolicy.
func (r *streamRedactor) redact(key streamKey, p []byte, mode string, policy headerValuePolicy) []byte {
	if r == nil || mode != RedactHeaders {
		return redactPayloadWithPolicy(p, mode, policy)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, tracked := r.state[key]
	switch {
	case startsHTTP1Message(p):
		r.set(key, streamInHeaders)
	case tracked && st == streamInBody:
		for i := range p {
			p[i] = 0 // a continuation of a message whose headers ended: body
		}
		return p
	case !tracked:
		return redactPayloadWithPolicy(p, mode, policy) // not an HTTP/1 stream we know
	}
	// A message start, or a continuation of headers still open: the headers
	// survive up to their terminator, as in the per-chunk rule.
	out := redactPayloadWithPolicy(p, mode, policy)
	if bytes.Contains(out, headerTerminator) {
		r.set(key, streamInBody)
	}
	return out
}

// set records a stream's state, evicting the oldest stream at the bound.
func (r *streamRedactor) set(key streamKey, st streamState) {
	if _, ok := r.state[key]; !ok {
		if len(r.order) >= r.max {
			delete(r.state, r.order[0])
			r.order = r.order[1:]
		}
		r.order = append(r.order, key)
	}
	r.state[key] = st
}
