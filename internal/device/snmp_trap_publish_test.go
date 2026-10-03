// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
)

// captureBus is a synchronous bus.Bus that records every Publish so the test can
// assert what actually left the agent onto the lane the control plane consumes.
type captureBus struct {
	msgs []bus.Message
}

func (c *captureBus) Publish(_ context.Context, topic string, key, value []byte) error {
	c.msgs = append(c.msgs, bus.Message{Topic: topic, Key: append([]byte(nil), key...), Value: append([]byte(nil), value...)})
	return nil
}
func (c *captureBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (c *captureBus) Close() error                                                 { return nil }

func (c *captureBus) trapEvents(t *testing.T) []*devicev1.DeviceTrapEvent {
	t.Helper()
	var out []*devicev1.DeviceTrapEvent
	for _, m := range c.msgs {
		if m.Topic != bus.DeviceTrapEventsTopic {
			continue
		}
		var batch devicev1.DeviceTrapEventBatch
		if err := proto.Unmarshal(m.Value, &batch); err != nil {
			t.Fatalf("trap batch on %s does not decode: %v", m.Topic, err)
		}
		out = append(out, batch.GetEvents()...)
	}
	return out
}

// TestSNMPTrapAcceptedEventIsPublishedTenantScopedAndDeduplicated is the RTP-10
// regression. An authenticated trap used to die in the device agent's in-process
// store — no bus topic or API ever read it, so nothing surfaced in the product.
// It must instead leave the agent as a tenant-scoped event on the bus lane the
// control plane consumes, with the tenant taken from the agent's enrolled
// identity (never the trap payload — G7-1), and a replayed identical trap must
// not produce a second event.
//
// Drives the REAL accept path (decodeAndRecord -> RecordPacket -> authenticate
// -> store -> publish) through the REAL production BusEmitter. Before the
// publish wiring exists the capture bus sees zero trap events and the first
// assertion fails as an assertion ("published trap events = 0, want 1"), not a
// build error.
func TestSNMPTrapAcceptedEventIsPublishedTenantScopedAndDeduplicated(t *testing.T) {
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	capBus := &captureBus{}
	store := NewMemoryTrapStore(10)
	receiver, err := NewTrapReceiver(TrapReceiverConfig{
		TenantID: "tenant-a",
		AgentID:  "device-agent-1",
		Now:      func() time.Time { return now },
		// The production path wires the BusEmitter (which implements
		// TrapEventEmitter) exactly like this.
		Emitter: NewBusEmitter(capBus, "tenant-a"),
		Sources: []TrapSource{{
			Name:       "core-v2c",
			Address:    "127.0.0.1",
			Transport:  TransportSNMPv2c,
			Credential: Credential{Community: "public-core"},
		}},
	}, store)
	if err != nil {
		t.Fatal(err)
	}

	remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2162}
	trap := snmpTrapFixtureV2C(t, "public-core", oidSNMPLinkDown, 7)

	if _, _, inserted, err := receiver.decodeAndRecord(context.Background(), trap, remote); err != nil || !inserted {
		t.Fatalf("first authenticated trap: inserted=%v err=%v", inserted, err)
	}

	published := capBus.trapEvents(t)
	if len(published) != 1 {
		t.Fatalf("published trap events = %d, want 1 (accepted trap never left the agent onto %s — RTP-10)",
			len(published), bus.DeviceTrapEventsTopic)
	}
	ev := published[0]
	if ev.GetTenantId() != "tenant-a" {
		t.Fatalf("published trap tenant = %q, want the agent's enrolled tenant %q (tenant must come from identity, not payload — G7-1)",
			ev.GetTenantId(), "tenant-a")
	}
	if ev.GetKind() != "snmp.trap.link_down" || ev.GetIfIndex() != 7 || ev.GetFingerprint() == "" {
		t.Fatalf("published trap not normalized: %+v", ev)
	}
	// Tenant-scoped at the bus layer: the record is keyed by the tenant, so a
	// tenant's traps stay partitioned (never a bare/empty key).
	wantKey := bus.TenantKey("tenant-a", "device-agent-1")
	if string(capBus.msgs[0].Key) != string(wantKey) {
		t.Fatalf("trap published with key %q, want tenant key %q (not tenant-scoped on the bus)",
			capBus.msgs[0].Key, wantKey)
	}

	// Replay the identical datagram: the store's fingerprint dedup must suppress
	// it so no second event is published (count stays 1).
	if _, _, inserted, err := receiver.decodeAndRecord(context.Background(), trap, remote); err != nil || inserted {
		t.Fatalf("duplicate replay: inserted=%v err=%v (want inserted=false)", inserted, err)
	}
	if got := len(capBus.trapEvents(t)); got != 1 {
		t.Fatalf("published trap events after replay = %d, want 1 (retransmitted trap was not deduplicated)", got)
	}
}
