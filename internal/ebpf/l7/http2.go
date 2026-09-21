// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package l7

import (
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2/hpack"
)

// HTTP/2 frame layout (RFC 7540 §4.1): 24-bit length, 8-bit type, 8-bit flags,
// 31-bit stream id, then the payload.
const frameHeaderLen = 9

const (
	frameData      = 0x0
	frameHeaders   = 0x1
	frameRSTStream = 0x3
)

const (
	flagEndStream  = 0x1
	flagEndHeaders = 0x4
	flagPadded     = 0x8
	flagPriority   = 0x20
)

// http2Parser parses HTTP/2 (and gRPC, which is HTTP/2 + an application/grpc
// content-type). Each direction has its own HPACK dynamic table, so it keeps a
// decoder per direction; calls are matched per stream id and emitted when the
// response stream ends (END_STREAM, including a gRPC trailers HEADERS, or RST).
type http2Parser struct {
	reqBuf, respBuf []byte
	reqDec, respDec *hpack.Decoder
	prefaceSkipped  bool
	streams         map[uint32]*h2stream
}

type h2stream struct {
	method, path, reqCT        string
	start                      time.Time
	reqBytes                   uint64
	status, grpcStatus, respCT string
	respBytes                  uint64
	haveReq                    bool
}

func newHTTP2Parser() *http2Parser {
	return &http2Parser{
		reqDec:  hpack.NewDecoder(4096, nil),
		respDec: hpack.NewDecoder(4096, nil),
		streams: map[uint32]*h2stream{},
	}
}

func (p *http2Parser) OnData(d DataEvent) []Call {
	if d.Kind == Request {
		// FUZZ-001: cap the per-direction buffer (an incomplete/oversized frame
		// stream would otherwise grow reqBuf without bound). Drop+reset.
		if len(p.reqBuf)+len(d.Payload) > l7MaxBufBytes {
			p.reqBuf = p.reqBuf[:0]
			return nil
		}
		p.reqBuf = append(p.reqBuf, d.Payload...)
		if !p.prefaceSkipped {
			if len(p.reqBuf) < len(http2Preface) {
				return nil
			}
			p.reqBuf = trimPrefix(p.reqBuf, http2Preface)
			p.prefaceSkipped = true
		}
		return p.consume(&p.reqBuf, p.reqDec, true, d.Time)
	}
	if len(p.respBuf)+len(d.Payload) > l7MaxBufBytes {
		p.respBuf = p.respBuf[:0]
		return nil
	}
	p.respBuf = append(p.respBuf, d.Payload...)
	return p.consume(&p.respBuf, p.respDec, false, d.Time)
}

func (p *http2Parser) Flush() []Call { return nil }

func (p *http2Parser) consume(buf *[]byte, dec *hpack.Decoder, isReq bool, ts time.Time) []Call {
	var calls []Call
	for {
		fr, rest, ok := nextFrame(*buf)
		if !ok {
			break
		}
		*buf = rest

		needsStream := fr.typ == frameHeaders || fr.typ == frameData || fr.typ == frameRSTStream
		if fr.stream == 0 || !needsStream {
			continue
		}
		st := p.streams[fr.stream]
		if st == nil {
			// FUZZ-001: cap concurrent streams (a flood of HEADERS opening
			// streams that never END_STREAM would otherwise grow without bound).
			// Evict the oldest unfinished stream when full.
			if len(p.streams) >= l7MaxPending {
				p.evictOldestStream()
			}
			st = &h2stream{start: ts}
			p.streams[fr.stream] = st
		}

		switch fr.typ {
		case frameHeaders:
			fields, err := dec.DecodeFull(headerBlock(fr))
			if err != nil {
				continue
			}
			applyFrameSize(st, isReq, fr)
			if isReq {
				st.haveReq = true
				st.start = ts
				for _, hf := range fields {
					switch hf.Name {
					case ":method":
						st.method = hf.Value
					case ":path":
						st.path = hf.Value
					case "content-type":
						st.reqCT = hf.Value
					}
				}
			} else {
				for _, hf := range fields {
					switch hf.Name {
					case ":status":
						st.status = hf.Value
					case "grpc-status":
						st.grpcStatus = hf.Value
					case "content-type":
						st.respCT = hf.Value
					}
				}
				if fr.flags&flagEndStream != 0 {
					if c, ok := p.finish(fr.stream, st, ts); ok {
						calls = append(calls, c)
					}
				}
			}
		case frameData:
			applyFrameSize(st, isReq, fr)
			if !isReq && fr.flags&flagEndStream != 0 {
				if c, ok := p.finish(fr.stream, st, ts); ok {
					calls = append(calls, c)
				}
			}
		case frameRSTStream:
			if !isReq {
				if c, ok := p.finish(fr.stream, st, ts); ok {
					calls = append(calls, c)
				}
			}
		}
	}
	return calls
}

func applyFrameSize(st *h2stream, isReq bool, fr h2frame) {
	n := uint64(len(fr.payload)) + frameHeaderLen
	if isReq {
		st.reqBytes += n
	} else {
		st.respBytes += n
	}
}

// evictOldestStream drops the least-recently-started unfinished stream
// (FUZZ-001), bounding p.streams under a flood of never-completing streams.
func (p *http2Parser) evictOldestStream() {
	var oldestID uint32
	var oldest time.Time
	first := true
	for id, st := range p.streams {
		if first || st.start.Before(oldest) {
			oldestID, oldest, first = id, st.start, false
		}
	}
	if !first {
		delete(p.streams, oldestID)
	}
}

func (p *http2Parser) finish(stream uint32, st *h2stream, ts time.Time) (Call, bool) {
	delete(p.streams, stream)
	if !st.haveReq {
		return Call{}, false
	}
	isGRPC := strings.HasPrefix(st.reqCT, "application/grpc") ||
		strings.HasPrefix(st.respCT, "application/grpc") || st.grpcStatus != ""
	c := Call{
		Start:     st.start,
		Latency:   ts.Sub(st.start),
		ReqBytes:  st.reqBytes,
		RespBytes: st.respBytes,
	}
	if isGRPC {
		c.Protocol = ProtoGRPC
		c.Method = strings.TrimPrefix(st.path, "/")
		c.Resource = st.path
		c.Status = st.grpcStatus
		if c.Status == "" {
			c.Status = "0" // OK when trailers omit grpc-status alongside HTTP 200
		}
		c.Error = c.Status != "0"
	} else {
		c.Protocol = ProtoHTTP2
		c.Method = st.method
		c.Resource = st.path
		c.Status = st.status
		if code, err := strconv.Atoi(st.status); err == nil {
			c.Error = code >= 400
		}
	}
	return c, true
}

type h2frame struct {
	typ     byte
	flags   byte
	stream  uint32
	payload []byte
}

// nextFrame extracts one complete HTTP/2 frame from buf, or ok=false if the
// frame is not yet fully captured.
func nextFrame(buf []byte) (fr h2frame, rest []byte, ok bool) {
	if len(buf) < frameHeaderLen {
		return fr, buf, false
	}
	length := int(buf[0])<<16 | int(buf[1])<<8 | int(buf[2])
	if len(buf) < frameHeaderLen+length {
		return fr, buf, false
	}
	fr.typ = buf[3]
	fr.flags = buf[4]
	fr.stream = (uint32(buf[5])<<24 | uint32(buf[6])<<16 | uint32(buf[7])<<8 | uint32(buf[8])) & 0x7fffffff
	fr.payload = buf[frameHeaderLen : frameHeaderLen+length]
	return fr, buf[frameHeaderLen+length:], true
}

// headerBlock returns the HPACK header-block fragment of a HEADERS frame,
// accounting for the PADDED and PRIORITY flags.
func headerBlock(fr h2frame) []byte {
	p := fr.payload
	if fr.flags&flagPadded != 0 {
		if len(p) == 0 {
			return nil
		}
		padLen := int(p[0])
		p = p[1:]
		if padLen <= len(p) {
			p = p[:len(p)-padLen]
		}
	}
	if fr.flags&flagPriority != 0 {
		if len(p) < 5 {
			return nil
		}
		p = p[5:]
	}
	return p
}

func trimPrefix(b, prefix []byte) []byte {
	if len(b) >= len(prefix) && string(b[:len(prefix)]) == string(prefix) {
		return b[len(prefix):]
	}
	return b
}
