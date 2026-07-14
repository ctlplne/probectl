// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package l7

import (
	"testing"
	"time"
)

func TestHTTP1MethodPathStatusLatency(t *testing.T) {
	p := newHTTP1Parser()
	t0 := time.Unix(100, 0)
	req := "GET /api/v1/users?id=7 HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"

	if c := p.OnData(DataEvent{Kind: Request, Time: t0, Payload: []byte(req)}); len(c) != 0 {
		t.Fatalf("request alone emitted %d calls, want 0", len(c))
	}
	calls := p.OnData(DataEvent{Kind: Response, Time: t0.Add(15 * time.Millisecond), Payload: []byte(resp)})
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	c := calls[0]
	if c.Protocol != ProtoHTTP1 || c.Method != "GET" || c.Resource != "/api/v1/users?id=7" || c.Status != "200" || c.Error {
		t.Errorf("call = %+v", c)
	}
	if c.Latency != 15*time.Millisecond {
		t.Errorf("latency = %v, want 15ms", c.Latency)
	}
}

func TestHTTP1PipeliningAndErrorStatus(t *testing.T) {
	p := newHTTP1Parser()
	t0 := time.Unix(0, 0)
	p.OnData(DataEvent{Kind: Request, Time: t0, Payload: []byte(
		"GET /a HTTP/1.1\r\nContent-Length: 0\r\n\r\nPOST /b HTTP/1.1\r\nContent-Length: 3\r\n\r\nxyz")})
	calls := p.OnData(DataEvent{Kind: Response, Time: t0, Payload: []byte(
		"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\nHTTP/1.1 500 err\r\nContent-Length: 0\r\n\r\n")})
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}
	if calls[0].Method != "GET" || calls[0].Resource != "/a" || calls[0].Status != "204" || calls[0].Error {
		t.Errorf("c0 = %+v", calls[0])
	}
	if calls[1].Method != "POST" || calls[1].Resource != "/b" || calls[1].Status != "500" || !calls[1].Error {
		t.Errorf("c1 = %+v", calls[1])
	}
}

func TestHTTP1IncrementalChunks(t *testing.T) {
	p := newHTTP1Parser()
	p.OnData(DataEvent{Kind: Request, Time: time.Unix(1, 0), Payload: []byte("GET /x HTTP/1.1\r\nHo")})
	if c := p.OnData(DataEvent{Kind: Request, Time: time.Unix(1, 0), Payload: []byte("st: y\r\nContent-Length: 0\r\n\r\n")}); len(c) != 0 {
		t.Fatalf("split request emitted %d calls, want 0", len(c))
	}
	calls := p.OnData(DataEvent{Kind: Response, Time: time.Unix(2, 0), Payload: []byte("HTTP/1.1 301 Moved\r\nContent-Length: 0\r\n\r\n")})
	if len(calls) != 1 || calls[0].Resource != "/x" || calls[0].Status != "301" {
		t.Errorf("calls = %+v", calls)
	}
}

func TestDetect(t *testing.T) {
	cases := []struct {
		head string
		port uint32
		want string
	}{
		{"GET / HTTP/1.1\r\n", 80, ProtoHTTP1},
		{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 443, ProtoHTTP2},
		{"", 53, ProtoDNS},
		{"", 9092, ProtoKafka},
		{"\x00\x00", 12345, ProtoUnknown},
	}
	for _, c := range cases {
		if got := Detect([]byte(c.head), c.port); got != c.want {
			t.Errorf("Detect(%q, %d) = %q, want %q", c.head, c.port, got, c.want)
		}
	}
}
