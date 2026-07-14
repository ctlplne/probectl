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

func TestManagerRoutesByConnAndDetects(t *testing.T) {
	m := NewManager()
	t0 := time.Unix(1, 0)
	m.OnData(7, 8080, DataEvent{Kind: Request, Time: t0, Payload: []byte("GET /health HTTP/1.1\r\nContent-Length: 0\r\n\r\n")})
	calls := m.OnData(7, 8080, DataEvent{Kind: Response, Time: t0.Add(time.Millisecond), Payload: []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")})
	if len(calls) != 1 || calls[0].Protocol != ProtoHTTP1 || calls[0].Resource != "/health" {
		t.Fatalf("calls = %+v", calls)
	}
	if m.Len() != 1 {
		t.Errorf("manager tracks %d conns, want 1", m.Len())
	}
	if got := m.Close(7); got != nil {
		t.Errorf("close returned %+v, want nil", got)
	}
	if m.Len() != 0 {
		t.Errorf("after close, tracks %d conns, want 0", m.Len())
	}
}

func TestTrackerUnknownProtocolNoCalls(t *testing.T) {
	tr := NewTracker(12345)
	calls := tr.OnData(DataEvent{Kind: Request, Time: time.Unix(0, 0), Payload: []byte("\x99\x98 garbage")})
	if len(calls) != 0 || tr.Protocol() != ProtoUnknown {
		t.Errorf("calls=%v proto=%q", calls, tr.Protocol())
	}
}
