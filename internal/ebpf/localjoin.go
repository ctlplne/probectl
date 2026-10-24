// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import "time"

// hostLocalJoin turns the two kernel sockets of a host-local connection into
// ONE client -> server edge (ING-24).
//
// The eBPF agent sees every socket on the host, so a connection whose client
// and server both run here is reported twice: once by the client socket
// (client process -> server address:port) and once by the server socket
// (client address -> server process:port). Each is correctly oriented, but
// together they draw two edges for one dependency. The join pairs them by
// 5-tuple: the server-side flow takes the client's endpoint (its process and
// workload) as its source, and the client-side flow then contributes no edge
// of its own. Client-side flows are held back for holdFor before they reach the
// service map, because the client's ESTABLISHED fires a moment before the
// server's; a client flow with no server side by then is an ordinary outbound
// flow and is folded in unchanged. Raw flows are published either way — only
// the edge aggregation is de-duplicated.
//
// Every map is bounded: a flood of half-observed connections can never grow
// the agent without limit (FUZZ-001 discipline).
type hostLocalJoin struct {
	holdFor time.Duration
	max     int

	clients  map[tupleKey]joinedEnd // client side seen, server side not yet
	servers  map[uint64]Endpoint    // server connKey -> the joined client endpoint
	merged   map[uint64]Endpoint    // client connKey -> the joined server endpoint
	deferred []deferredFlow         // client-side flows not yet folded into the map
}

type tupleKey struct {
	clientAddr string
	clientPort uint32
	serverAddr string
	serverPort uint32
}

type joinedEnd struct {
	ep      Endpoint
	connKey uint64
	seen    time.Time
}

type deferredFlow struct {
	f  Flow
	at time.Time
}

const (
	defaultJoinHold = time.Second
	defaultJoinMax  = 65536
)

func newHostLocalJoin() *hostLocalJoin {
	return &hostLocalJoin{
		holdFor: defaultJoinHold,
		max:     defaultJoinMax,
		clients: map[tupleKey]joinedEnd{},
		servers: map[uint64]Endpoint{},
		merged:  map[uint64]Endpoint{},
	}
}

func flowTuple(f Flow) tupleKey {
	return tupleKey{
		clientAddr: f.Source.Address, clientPort: f.Source.Port,
		serverAddr: f.Destination.Address, serverPort: f.Destination.Port,
	}
}

// admit decides what one enriched flow contributes to the service map. It
// returns the flow to fold in now (possibly re-sourced to the joined client)
// and whether there is one; a client-side flow is held (ok=false) and comes
// back out of release. fold receives held flows released early because the
// hold queue hit its bound.
func (j *hostLocalJoin) admit(f Flow, now time.Time, fold func(Flow)) (Flow, bool) {
	switch f.role {
	case roleClient:
		// Always held, even when the server side already claimed the
		// connection: release drops claimed flows in arrival order, so the
		// claim outlives every client-side flow of the connection.
		if f.State != StateClose {
			if len(j.clients) >= j.max {
				j.clients = map[tupleKey]joinedEnd{} // bounded: forget, never grow
			}
			j.clients[flowTuple(f)] = joinedEnd{ep: f.Source, connKey: f.connKey, seen: now}
		}
		if len(j.deferred) >= j.max {
			j.releaseAll(fold) // bounded: fold the held flows in unjoined
		}
		j.deferred = append(j.deferred, deferredFlow{f: f, at: now})
		return Flow{}, false
	case roleServer:
		if f.connKey != 0 {
			if ep, ok := j.servers[f.connKey]; ok {
				f.Source = ep
				if f.State == StateClose {
					delete(j.servers, f.connKey)
				}
				return f, true
			}
		}
		t := flowTuple(f)
		if c, ok := j.clients[t]; ok {
			delete(j.clients, t)
			f.Source = c.ep
			if f.connKey != 0 && f.State != StateClose {
				if len(j.servers) >= j.max {
					j.servers = map[uint64]Endpoint{}
				}
				j.servers[f.connKey] = c.ep
			}
			if c.connKey != 0 {
				if len(j.merged) >= j.max {
					j.merged = map[uint64]Endpoint{}
				}
				j.merged[c.connKey] = f.Destination
			}
		}
		return f, true
	default:
		return f, true
	}
}

// release returns the held client-side flows whose hold has expired (all of
// them when final), dropping the ones a server side has since claimed.
func (j *hostLocalJoin) release(now time.Time, final bool) []Flow {
	var out []Flow
	keep := j.deferred[:0]
	for _, d := range j.deferred {
		if !final && now.Sub(d.at) < j.holdFor {
			keep = append(keep, d)
			continue
		}
		if _, done := j.merged[d.f.connKey]; done && d.f.connKey != 0 {
			if d.f.State == StateClose {
				delete(j.merged, d.f.connKey)
			}
			continue
		}
		out = append(out, d.f)
	}
	j.deferred = keep
	for t, c := range j.clients {
		if final || now.Sub(c.seen) >= 2*j.holdFor {
			delete(j.clients, t)
		}
	}
	return out
}

func (j *hostLocalJoin) releaseAll(fold func(Flow)) {
	for _, f := range j.release(time.Time{}, true) {
		if fold != nil {
			fold(f)
		}
	}
}
