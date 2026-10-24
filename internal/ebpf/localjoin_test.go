// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func serverFlow(client, server Endpoint, state string, key uint64) Flow {
	return Flow{TenantID: "t", Source: client, Destination: server, Transport: TransportTCP,
		Direction: DirectionIngress, State: state, role: roleServer, connKey: key}
}

func clientFlow(client, server Endpoint, state string, key uint64) Flow {
	return Flow{TenantID: "t", Source: client, Destination: server, Transport: TransportTCP,
		Direction: DirectionEgress, State: state, role: roleClient, connKey: key}
}

func runFlows(t *testing.T, flows []Flow) *captureEmitter {
	t.Helper()
	cfg := Default()
	cfg.TenantID = "t"
	cfg.FlushInterval = time.Hour
	em := &captureEmitter{}
	a := newAgentWith(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), &sliceSource{flows: flows}, NopEnricher{}, em)
	if err := a.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	return em
}

// TestInboundConnectionsMakeOneEdgeOnTheListenPort is the ING-24 unit
// regression: ten inbound connections from one remote client to :443 used to
// draw ten server -> client edges keyed on the client's ephemeral ports. They
// must draw ONE client -> server edge keyed on 443, owned by the server.
func TestInboundConnectionsMakeOneEdgeOnTheListenPort(t *testing.T) {
	server := Endpoint{Address: "10.0.0.5", Port: 443, PID: 900, Workload: "nginx"}
	var flows []Flow
	for i := 0; i < 10; i++ {
		client := Endpoint{Address: "10.0.0.9", Port: uint32(51000 + i)}
		flows = append(flows,
			serverFlow(client, server, StateEstablished, uint64(100+i)),
			serverFlow(client, server, StateClose, uint64(100+i)))
	}
	em := runFlows(t, flows)
	if len(em.edges) != 1 {
		t.Fatalf("edges = %d, want 1: %+v", len(em.edges), em.edges)
	}
	e := em.edges[0]
	if e.Source != "10.0.0.9" || e.Destination != "nginx" || e.DestPort != 443 || e.Connections != 10 {
		t.Fatalf("edge = %+v, want 10.0.0.9 -> nginx:443 with 10 connections", e)
	}
	for _, f := range em.flows {
		if got := f.toProto().GetWorkload(); got != "nginx" {
			t.Fatalf("published inbound flow names workload %q, want the server nginx", got)
		}
	}
	if got := em.flows[0].toProto(); got.GetPid() != 900 || got.GetDirection() != DirectionIngress {
		t.Fatalf("published inbound flow pid/direction = %d/%q, want the server's 900/ingress", got.GetPid(), got.GetDirection())
	}
}

// TestHostLocalConnectionJoinsIntoOneEdge: both sockets of a connection on the
// same host are observed; they must draw one client-process -> server-process
// edge, while both raw flows are still published.
func TestHostLocalConnectionJoinsIntoOneEdge(t *testing.T) {
	cli := Endpoint{Address: "127.0.0.1", Port: 40001, PID: 10, Workload: "curl"}
	srvLocal := Endpoint{Address: "127.0.0.1", Port: 8080, PID: 20, Workload: "api"}
	em := runFlows(t, []Flow{
		clientFlow(cli, Endpoint{Address: "127.0.0.1", Port: 8080}, StateEstablished, 1),
		serverFlow(Endpoint{Address: "127.0.0.1", Port: 40001}, srvLocal, StateEstablished, 2),
		clientFlow(cli, Endpoint{Address: "127.0.0.1", Port: 8080}, StateClose, 1),
		serverFlow(Endpoint{Address: "127.0.0.1", Port: 40001}, srvLocal, StateClose, 2),
	})
	if len(em.edges) != 1 {
		t.Fatalf("edges = %d, want 1 joined edge: %+v", len(em.edges), em.edges)
	}
	if e := em.edges[0]; e.Source != "curl" || e.Destination != "api" || e.DestPort != 8080 || e.Connections != 1 {
		t.Fatalf("joined edge = %+v, want curl -> api:8080 once", e)
	}
	if len(em.flows) != 4 {
		t.Fatalf("raw flows = %d, want all 4 published", len(em.flows))
	}
}

// TestOutboundClientFlowIsFoldedInAfterTheHold: a client-side flow whose server
// is elsewhere is an ordinary outbound edge once the hold expires.
func TestOutboundClientFlowIsFoldedInAfterTheHold(t *testing.T) {
	j := newHostLocalJoin()
	now := time.Unix(1000, 0)
	cli := Endpoint{Address: "10.0.0.5", Port: 40001, PID: 10, Workload: "curl"}
	if _, ok := j.admit(clientFlow(cli, Endpoint{Address: "93.184.216.34", Port: 443}, StateEstablished, 7), now, nil); ok {
		t.Fatal("client-side flow must be held for its server side")
	}
	if got := j.release(now.Add(10*time.Millisecond), false); len(got) != 0 {
		t.Fatalf("released %d flows before the hold expired", len(got))
	}
	got := j.release(now.Add(2*time.Second), false)
	if len(got) != 1 || got[0].Destination.Port != 443 {
		t.Fatalf("released %+v, want the outbound flow", got)
	}
	if len(j.clients) != 0 {
		t.Fatalf("expired client records not swept: %d", len(j.clients))
	}
}

// TestHostLocalJoinIsBounded: the hold queue and maps never exceed their bound.
func TestHostLocalJoinIsBounded(t *testing.T) {
	j := newHostLocalJoin()
	j.max = 8
	folded := 0
	now := time.Unix(1000, 0)
	for i := 0; i < 100; i++ {
		c := Endpoint{Address: "10.0.0.5", Port: uint32(40000 + i)}
		j.admit(clientFlow(c, Endpoint{Address: "10.0.0.6", Port: 80}, StateEstablished, uint64(i+1)), now, func(Flow) { folded++ })
	}
	if len(j.deferred) > j.max || len(j.clients) > j.max {
		t.Fatalf("join grew past its bound: deferred=%d clients=%d", len(j.deferred), len(j.clients))
	}
	if folded == 0 {
		t.Fatal("overflowing held flows must be folded in, not lost")
	}
}
