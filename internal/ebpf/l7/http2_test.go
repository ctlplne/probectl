// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package l7

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

func frameBytes(typ, flags byte, stream uint32, payload []byte) []byte {
	hdr := make([]byte, frameHeaderLen)
	n := len(payload)
	hdr[0], hdr[1], hdr[2] = byte(n>>16), byte(n>>8), byte(n)
	hdr[3], hdr[4] = typ, flags
	hdr[5], hdr[6], hdr[7], hdr[8] = byte(stream>>24), byte(stream>>16), byte(stream>>8), byte(stream)
	return append(hdr, payload...)
}

func headersFrame(enc *hpack.Encoder, hb *bytes.Buffer, stream uint32, endStream bool, kv ...string) []byte {
	hb.Reset()
	for i := 0; i+1 < len(kv); i += 2 {
		_ = enc.WriteField(hpack.HeaderField{Name: kv[i], Value: kv[i+1]})
	}
	flags := byte(flagEndHeaders)
	if endStream {
		flags |= flagEndStream
	}
	return frameBytes(frameHeaders, flags, stream, append([]byte(nil), hb.Bytes()...))
}

func TestHTTP2RequestResponse(t *testing.T) {
	p := newHTTP2Parser()
	var rb, sb bytes.Buffer
	reqEnc, respEnc := hpack.NewEncoder(&rb), hpack.NewEncoder(&sb)
	t0 := time.Unix(10, 0)

	req := append([]byte(nil), http2Preface...)
	req = append(req, headersFrame(reqEnc, &rb, 1, true, ":method", "GET", ":path", "/v2/items", "content-type", "application/json")...)
	if c := p.OnData(DataEvent{Kind: Request, Time: t0, Payload: req}); len(c) != 0 {
		t.Fatalf("request emitted %d calls, want 0", len(c))
	}
	resp := headersFrame(respEnc, &sb, 1, true, ":status", "200", "content-type", "application/json")
	calls := p.OnData(DataEvent{Kind: Response, Time: t0.Add(8 * time.Millisecond), Payload: resp})
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	c := calls[0]
	if c.Protocol != ProtoHTTP2 || c.Method != "GET" || c.Resource != "/v2/items" || c.Status != "200" || c.Error {
		t.Errorf("call = %+v", c)
	}
	if c.Latency != 8*time.Millisecond {
		t.Errorf("latency = %v", c.Latency)
	}
}

func TestHTTP2GRPCWithTrailerStatus(t *testing.T) {
	p := newHTTP2Parser()
	var rb, sb bytes.Buffer
	reqEnc, respEnc := hpack.NewEncoder(&rb), hpack.NewEncoder(&sb)
	t0 := time.Unix(0, 0)

	req := append([]byte(nil), http2Preface...)
	req = append(req, headersFrame(reqEnc, &rb, 1, true, ":method", "POST", ":path", "/pkg.Svc/DoThing", "content-type", "application/grpc")...)
	p.OnData(DataEvent{Kind: Request, Time: t0, Payload: req})

	// response HEADERS (200, no END_STREAM), then trailers HEADERS w/ grpc-status (END_STREAM)
	respHdr := headersFrame(respEnc, &sb, 1, false, ":status", "200", "content-type", "application/grpc")
	trailer := headersFrame(respEnc, &sb, 1, true, "grpc-status", "13") // INTERNAL
	calls := p.OnData(DataEvent{Kind: Response, Time: t0.Add(time.Millisecond), Payload: append(respHdr, trailer...)})
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	c := calls[0]
	if c.Protocol != ProtoGRPC || c.Method != "pkg.Svc/DoThing" || c.Resource != "/pkg.Svc/DoThing" || c.Status != "13" || !c.Error {
		t.Errorf("call = %+v", c)
	}
}
