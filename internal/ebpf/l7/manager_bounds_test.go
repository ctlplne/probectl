// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package l7

import (
	"testing"
	"time"
)

// TestManagerCapBounded feeds far more distinct connection ids than the cap and
// asserts Manager.conns never exceeds it, with the eviction counter rising
// (FUZZ-001). Pre-fix the map was unbounded and would hold all N.
func TestManagerCapBounded(t *testing.T) {
	m := NewManager()
	m.SetBounds(32, time.Minute)
	base := time.Unix(0, 0)
	req := []byte("GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
	const n = 4000
	for i := 0; i < n; i++ {
		m.OnData(uint64(i+1), 80, DataEvent{Kind: Request, Time: base.Add(time.Duration(i) * time.Millisecond), Payload: req})
	}
	if m.Len() > 32 {
		t.Errorf("Manager.Len() = %d, exceeds cap 32", m.Len())
	}
	if m.Evicted() == 0 {
		t.Error("Evicted() == 0 — cap never enforced under N>>cap churn")
	}
}

// TestManagerIdlePrune abandons connections past the idle TTL (FUZZ-001).
func TestManagerIdlePrune(t *testing.T) {
	m := NewManager()
	m.SetBounds(0, time.Minute) // no cap, TTL only
	base := time.Unix(0, 0)
	req := []byte("GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
	for i := 0; i < 5; i++ {
		m.OnData(uint64(i+1), 80, DataEvent{Kind: Request, Time: base, Payload: req})
	}
	if m.Len() != 5 {
		t.Fatalf("setup Len = %d, want 5", m.Len())
	}
	pruned := m.Prune(base.Add(2 * time.Minute))
	if pruned != 5 || m.Len() != 0 {
		t.Errorf("Prune dropped %d (Len now %d), want 5 dropped / 0 remaining", pruned, m.Len())
	}
}

// TestHTTP1PendingBounded floods pipelined requests with no responses and
// asserts the pending slice stays <= cap (FUZZ-001).
func TestHTTP1PendingBounded(t *testing.T) {
	p := newHTTP1Parser()
	base := time.Unix(0, 0)
	req := []byte("GET /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
	for i := 0; i < l7MaxPending*3; i++ {
		p.OnData(DataEvent{Kind: Request, Time: base, Payload: req})
	}
	if len(p.pending) > l7MaxPending {
		t.Errorf("http1 pending = %d, exceeds cap %d", len(p.pending), l7MaxPending)
	}
}

// TestHTTP1BufferBounded feeds a never-terminating dribble and asserts reqBuf
// resets rather than growing without bound (FUZZ-001).
func TestHTTP1BufferBounded(t *testing.T) {
	p := newHTTP1Parser()
	chunk := make([]byte, 64*1024) // no CRLFCRLF terminator → never a full message
	for i := 0; i < 1000; i++ {
		p.OnData(DataEvent{Kind: Request, Payload: chunk})
		if len(p.reqBuf) > l7MaxBufBytes {
			t.Fatalf("http1 reqBuf = %d, exceeds cap %d", len(p.reqBuf), l7MaxBufBytes)
		}
	}
}
