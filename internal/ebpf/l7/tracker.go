// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package l7

import (
	"sync/atomic"
	"time"
)

// Tracker parses one connection: it detects the protocol from the first request
// bytes (plus the destination-port hint) and delegates to the matching parser.
type Tracker struct {
	dstPort  uint32
	proto    string
	parser   Parser
	lastSeen time.Time // FUZZ-001: drives the Manager's idle/LRU eviction
}

// NewTracker returns a Tracker for a connection to dstPort.
func NewTracker(dstPort uint32) *Tracker { return &Tracker{dstPort: dstPort} }

// OnData feeds one plaintext chunk and returns any completed calls.
func (t *Tracker) OnData(d DataEvent) []Call {
	if t.parser == nil {
		if d.Kind != Request {
			return nil // need request bytes to detect; a stray early response is dropped
		}
		t.proto = Detect(d.Payload, t.dstPort)
		t.parser = parserFor(t.proto)
		if t.parser == nil {
			return nil
		}
	}
	return t.parser.OnData(d)
}

// Flush returns any calls still buffered (e.g. on connection close).
func (t *Tracker) Flush() []Call {
	if t.parser == nil {
		return nil
	}
	return t.parser.Flush()
}

// Protocol returns the detected protocol ("" until detected).
func (t *Tracker) Protocol() string { return t.proto }

func parserFor(proto string) Parser {
	switch proto {
	case ProtoHTTP1:
		return newHTTP1Parser()
	case ProtoHTTP2, ProtoGRPC:
		return newHTTP2Parser()
	case ProtoDNS:
		return newDNSParser()
	case ProtoKafka:
		return newKafkaParser()
	case ProtoPostgres:
		return newPostgresParser()
	case ProtoMySQL:
		return newMySQLParser()
	default:
		return nil
	}
}

// FUZZ-001: a privileged eBPF agent on a busy host sees an unbounded stream of
// distinct connection ids (the SSL* pointer with no socket-close correlation
// yet — source_live_l7_linux.go). Without a cap, Manager.conns grows forever
// (one *Tracker, plus its parser's per-direction buffers, per connection). So
// the Manager bounds its live set: an idle TTL abandons connections not seen
// within the window, and a hard cap evicts the least-recently-seen tracker
// (flushing it first) — the map can never exceed maxConns. Evictions are
// counted, never silent. These defaults mirror the DNS parser's bounded map.
const (
	defaultMaxConns = 8192             // hard cap on live trackers
	defaultConnTTL  = 60 * time.Second // a connection idle this long is abandoned
)

// Manager multiplexes many connections, keyed by a connection id from the
// capture layer (e.g. a socket cookie / fd identity). It is bounded (FUZZ-001).
type Manager struct {
	conns    map[uint64]*Tracker
	maxConns int
	idleTTL  time.Duration
	evicted  atomic.Uint64
}

// NewManager returns an empty Manager with the default conn cap + idle TTL.
func NewManager() *Manager {
	return &Manager{
		conns:    map[uint64]*Tracker{},
		maxConns: defaultMaxConns,
		idleTTL:  defaultConnTTL,
	}
}

// SetBounds overrides the live-connection cap and idle TTL (FUZZ-001). A
// non-positive value leaves that bound UNSET (0 = unbounded — lightweight/test
// mode only).
func (m *Manager) SetBounds(maxConns int, idleTTL time.Duration) {
	m.maxConns = maxConns
	m.idleTTL = idleTTL
}

// Evicted reports how many trackers were dropped by the cap or idle-TTL.
func (m *Manager) Evicted() uint64 { return m.evicted.Load() }

// OnData routes a data event for connID (to dstPort) to its tracker, stamping
// its last-seen time and enforcing the connection cap.
func (m *Manager) OnData(connID uint64, dstPort uint32, d DataEvent) []Call {
	t := m.conns[connID]
	if t == nil {
		if m.maxConns > 0 && len(m.conns) >= m.maxConns {
			m.evictOldest()
		}
		t = NewTracker(dstPort)
		m.conns[connID] = t
	}
	if !d.Time.IsZero() {
		t.lastSeen = d.Time
	} else {
		t.lastSeen = time.Now()
	}
	return t.OnData(d)
}

// evictOldest flushes-and-drops the least-recently-seen tracker (counted). The
// flushed calls are discarded: the connection is being abandoned under pressure,
// and surfacing the eviction count is the honest signal (not a silent loss).
func (m *Manager) evictOldest() {
	var oldestID uint64
	var oldest time.Time
	first := true
	for id, t := range m.conns {
		if first || t.lastSeen.Before(oldest) {
			oldestID, oldest, first = id, t.lastSeen, false
		}
	}
	if !first {
		delete(m.conns, oldestID)
		m.evicted.Add(1)
	}
}

// Prune abandons connections not seen within idleTTL of now (FUZZ-001). No-op
// when idleTTL is unset. Returns the number pruned.
func (m *Manager) Prune(now time.Time) int {
	if m.idleTTL <= 0 {
		return 0
	}
	cutoff := now.Add(-m.idleTTL)
	n := 0
	for id, t := range m.conns {
		if t.lastSeen.Before(cutoff) {
			delete(m.conns, id)
			n++
		}
	}
	m.evicted.Add(uint64(n))
	return n
}

// Close flushes and removes a connection's tracker.
func (m *Manager) Close(connID uint64) []Call {
	t := m.conns[connID]
	if t == nil {
		return nil
	}
	delete(m.conns, connID)
	return t.Flush()
}

// Len returns the number of tracked connections.
func (m *Manager) Len() int { return len(m.conns) }
