// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package l7

import (
	"bytes"
	"strconv"
	"strings"
	"time"
)

// http1Parser parses HTTP/1.x. It buffers each direction, extracts complete
// messages (headers + Content-Length body), and stitches request→response in
// order (HTTP/1.1 is sequential per connection, so the Nth response answers the
// Nth request — pipelining included).
type http1Parser struct {
	reqBuf  []byte
	respBuf []byte
	pending []pendingReq
}

type pendingReq struct {
	method string
	path   string
	start  time.Time
	bytes  uint64
}

func newHTTP1Parser() *http1Parser { return &http1Parser{} }

func (p *http1Parser) OnData(d DataEvent) []Call {
	if d.Kind == Request {
		// FUZZ-001: cap the per-direction buffer. A peer that dribbles bytes but
		// never completes a message (or non-HTTP bytes on an HTTP port) would
		// otherwise grow reqBuf without bound. Drop+reset on overflow.
		if len(p.reqBuf)+len(d.Payload) > l7MaxBufBytes {
			p.reqBuf = p.reqBuf[:0]
			return nil
		}
		p.reqBuf = append(p.reqBuf, d.Payload...)
		for {
			msg, rest, ok := scanHTTP1Message(p.reqBuf)
			if !ok {
				break
			}
			p.reqBuf = rest
			if method, path, ok := parseRequestLine(msg); ok {
				// FUZZ-001: cap in-flight unmatched requests; drop OLDEST when full.
				if len(p.pending) >= l7MaxPending {
					p.pending = p.pending[1:]
				}
				p.pending = append(p.pending, pendingReq{method: method, path: path, start: d.Time, bytes: uint64(len(msg))})
			}
		}
		return nil
	}

	var calls []Call
	if len(p.respBuf)+len(d.Payload) > l7MaxBufBytes {
		p.respBuf = p.respBuf[:0]
		return nil
	}
	p.respBuf = append(p.respBuf, d.Payload...)
	for {
		msg, rest, ok := scanHTTP1Message(p.respBuf)
		if !ok {
			break
		}
		p.respBuf = rest
		status, ok := parseStatusLine(msg)
		if !ok {
			continue
		}
		call := Call{
			Protocol:  ProtoHTTP1,
			Status:    strconv.Itoa(status),
			Error:     status >= 400,
			RespBytes: uint64(len(msg)),
		}
		if len(p.pending) > 0 {
			req := p.pending[0]
			p.pending = p.pending[1:]
			call.Method = req.method
			call.Resource = req.path
			call.Start = req.start
			call.Latency = d.Time.Sub(req.start)
			call.ReqBytes = req.bytes
		}
		calls = append(calls, call)
	}
	return calls
}

func (p *http1Parser) Flush() []Call { return nil }

// scanHTTP1Message returns the next complete HTTP/1 message (headers + body) in
// buf, or ok=false if not fully captured yet. The body length comes from
// Content-Length; chunked/close-delimited bodies are a documented limit.
func scanHTTP1Message(buf []byte) (msg, rest []byte, ok bool) {
	idx := bytes.Index(buf, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil, buf, false
	}
	headerEnd := idx + 4
	total := headerEnd + contentLength(buf[:headerEnd])
	if total > len(buf) {
		return nil, buf, false
	}
	return buf[:total], buf[total:], true
}

func contentLength(header []byte) int {
	lines := bytes.Split(header, []byte("\r\n"))
	for _, ln := range lines[1:] { // skip the request/status line
		if len(ln) == 0 {
			break
		}
		colon := bytes.IndexByte(ln, ':')
		if colon < 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(string(ln[:colon])), "content-length") {
			if n, err := strconv.Atoi(strings.TrimSpace(string(ln[colon+1:]))); err == nil && n >= 0 {
				return n
			}
		}
	}
	return 0
}

func parseRequestLine(msg []byte) (method, path string, ok bool) {
	end := bytes.Index(msg, []byte("\r\n"))
	if end < 0 {
		return "", "", false
	}
	parts := strings.SplitN(string(msg[:end]), " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func parseStatusLine(msg []byte) (int, bool) {
	end := bytes.Index(msg, []byte("\r\n"))
	if end < 0 {
		return 0, false
	}
	parts := strings.SplitN(string(msg[:end]), " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return 0, false
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, false
	}
	return code, true
}
