// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package a2a

import "testing"

func TestBrokerFlow(t *testing.T) {
	b := NewBroker()
	const tenant, resp, init = "t1", "agent-A", "agent-B"

	sid, err := b.StartSession(tenant, resp, init, "udp", 4)
	if err != nil {
		t.Fatal(err)
	}

	// The initiator has nothing until the responder reports its endpoint.
	if _, ok := b.PollFor(tenant, init); ok {
		t.Fatal("initiator should have no task before the endpoint is reported")
	}
	// The responder gets its task.
	rt, ok := b.PollFor(tenant, resp)
	if !ok || rt.Role != RoleResponder || rt.SessionID != sid || rt.Mode != "udp" || rt.Count != 4 || rt.PeerAgentID != init {
		t.Fatalf("responder task = %+v, ok=%v", rt, ok)
	}
	// Polling again yields nothing (at-most-once).
	if _, ok := b.PollFor(tenant, resp); ok {
		t.Error("responder task should be delivered once")
	}

	if err := b.ReportEndpoint(tenant, resp, sid, "10.0.0.5", 41000); err != nil {
		t.Fatal(err)
	}
	it, ok := b.PollFor(tenant, init)
	if !ok || it.Role != RoleInitiator || it.ResponderHost != "10.0.0.5" || it.ResponderPort != 41000 || it.PeerAgentID != resp {
		t.Fatalf("initiator task = %+v, ok=%v", it, ok)
	}
}

func TestBrokerTenantIsolation(t *testing.T) {
	b := NewBroker()
	sid, err := b.StartSession("t1", "A", "B", "tcp", 3)
	if err != nil {
		t.Fatal(err)
	}
	// A same-named agent in another tenant gets nothing.
	if _, ok := b.PollFor("t2", "A"); ok {
		t.Error("cross-tenant poll must not return another tenant's task")
	}
	// An endpoint report from the wrong tenant (even with the right agent id and
	// session id) is rejected.
	if err := b.ReportEndpoint("t2", "A", sid, "10.0.0.5", 5000); err == nil {
		t.Error("cross-tenant ReportEndpoint must be rejected")
	}
	// A report from the initiator (not the responder) is rejected.
	if err := b.ReportEndpoint("t1", "B", sid, "10.0.0.5", 5000); err == nil {
		t.Error("non-responder ReportEndpoint must be rejected")
	}
}

func TestBrokerValidation(t *testing.T) {
	b := NewBroker()
	if _, err := b.StartSession("t1", "A", "A", "udp", 1); err == nil {
		t.Error("responder == initiator should error")
	}
	if _, err := b.StartSession("t1", "A", "B", "icmp", 1); err == nil {
		t.Error("unknown mode should error")
	}
	if err := b.ReportEndpoint("t1", "A", "no-such-session", "h", 1); err == nil {
		t.Error("unknown session should error")
	}
}
