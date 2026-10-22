// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/device"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
)

// memTrapStore is a tenant-partitioned, fingerprint-idempotent fake of the
// Postgres trap store.
type memTrapStore struct {
	mu      sync.Mutex
	rows    map[string][]device.TrapRecord
	seen    map[string]bool
	failErr error
}

func newMemTrapStore() *memTrapStore {
	return &memTrapStore{rows: map[string][]device.TrapRecord{}, seen: map[string]bool{}}
}

func (m *memTrapStore) RecordTrapEvent(_ context.Context, tenant string, rec device.TrapRecord) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failErr != nil {
		return false, m.failErr
	}
	if rec.TenantID != tenant {
		return false, errors.New("tenant scope mismatch")
	}
	key := tenant + "|" + rec.AgentID + "|" + rec.Fingerprint
	if m.seen[key] {
		return false, nil
	}
	m.seen[key] = true
	m.rows[tenant] = append(m.rows[tenant], rec)
	return true, nil
}

func (m *memTrapStore) ListTrapEvents(_ context.Context, tenant string, _ device.TrapFilter) ([]device.TrapRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]device.TrapRecord(nil), m.rows[tenant]...), false, nil
}

func trapEvent(tenant, agent, fp string) *devicev1.DeviceTrapEvent {
	return &devicev1.DeviceTrapEvent{
		TenantId: tenant, AgentId: agent, DeviceAddress: "10.0.0.1", SourceAddress: "10.0.0.1",
		Source: device.SourceSNMPTrap, AuthPrincipal: "core-sw1", Version: "snmpv2c",
		Kind: "snmp.trap.link_down", Severity: "warning", TrapOid: ".1.3.6.1.6.3.1.1.5.3",
		IfIndex: 2, Fingerprint: fp, ObservedAtUnixNano: time.Now().UnixNano(),
		Varbinds: []*devicev1.DeviceTrapVarBind{{Oid: ".1.3.6.1.2.1.2.2.1.1.2", Type: "Integer", Value: "2"}},
	}
}

func trapMsg(t *testing.T, events ...*devicev1.DeviceTrapEvent) bus.Message {
	t.Helper()
	raw, err := proto.Marshal(&devicev1.DeviceTrapEventBatch{Events: events})
	if err != nil {
		t.Fatal(err)
	}
	return bus.Message{Topic: bus.DeviceTrapEventsTopic, Key: []byte("k"), Value: raw}
}

func TestDeviceTrapConsumerLaneTenantIsAuthoritative(t *testing.T) {
	st := newMemTrapStore()
	c := NewDeviceTrapConsumer(nil, st, nil).WithTenantBinding(&fakeBinding{pairs: map[[2]string]bool{
		{"tenant-b", "agent-b"}: true,
	}})
	// The payload claims tenant A; it arrived on B's namespaced lane.
	if err := c.handleLane(context.Background(), trapMsg(t, trapEvent("tenant-a", "agent-b", "fp-1")), "tenant-b"); err != nil {
		t.Fatal(err)
	}
	if got := st.rows["tenant-a"]; len(got) != 0 {
		t.Fatalf("a record on tenant B's lane was stored for the tenant its payload named: %+v", got)
	}
	got := st.rows["tenant-b"]
	if len(got) != 1 || got[0].TenantID != "tenant-b" || got[0].AgentID != "agent-b" || got[0].TrapName != "linkDown" {
		t.Fatalf("tenant B rows = %+v, want the one trap stamped with its lane tenant", got)
	}
	if s := c.integrityStats(); s.Received != 1 || s.Stored != 1 {
		t.Fatalf("ledger = %+v", s)
	}
}

func TestDeviceTrapConsumerRejectsUnverifiedBatches(t *testing.T) {
	binding := &fakeBinding{pairs: map[[2]string]bool{{"tenant-a", "agent-a"}: true}}
	cases := []struct {
		name   string
		strict bool
		lane   string
		events []*devicev1.DeviceTrapEvent
	}{
		{name: "strict shared lane", strict: true, events: []*devicev1.DeviceTrapEvent{trapEvent("tenant-a", "agent-a", "fp")}},
		{name: "unregistered pair on shared lane", events: []*devicev1.DeviceTrapEvent{trapEvent("tenant-a", "agent-x", "fp")}},
		{name: "agent not in lane tenant", lane: "tenant-b", events: []*devicev1.DeviceTrapEvent{trapEvent("tenant-b", "agent-a", "fp")}},
		{name: "no tenant", events: []*devicev1.DeviceTrapEvent{trapEvent("", "agent-a", "fp")}},
		{name: "no agent", lane: "tenant-a", events: []*devicev1.DeviceTrapEvent{trapEvent("tenant-a", "", "fp")}},
		{name: "mixed agents", lane: "tenant-a", events: []*devicev1.DeviceTrapEvent{
			trapEvent("tenant-a", "agent-a", "fp-1"), trapEvent("tenant-a", "agent-b", "fp-2")}},
		{name: "mixed tenants", events: []*devicev1.DeviceTrapEvent{
			trapEvent("tenant-a", "agent-a", "fp-1"), trapEvent("tenant-b", "agent-a", "fp-2")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newMemTrapStore()
			c := NewDeviceTrapConsumer(nil, st, nil).WithTenantBinding(binding).WithStrictTenantLanes(tc.strict)
			if err := c.handleLane(context.Background(), trapMsg(t, tc.events...), tc.lane); err != nil {
				t.Fatalf("a rejected batch must be acked (dropped), got %v", err)
			}
			if len(st.rows) != 0 {
				t.Fatalf("rejected batch stored rows: %+v", st.rows)
			}
			if s := c.integrityStats(); s.TenantRejected != 1 {
				t.Fatalf("ledger = %+v, want one tenant rejection", s)
			}
		})
	}
}

func TestDeviceTrapConsumerIsIdempotentOnRedelivery(t *testing.T) {
	st := newMemTrapStore()
	c := NewDeviceTrapConsumer(nil, st, nil)
	msg := trapMsg(t, trapEvent("tenant-a", "agent-a", "fp-1"))
	for i := 0; i < 3; i++ {
		if err := c.handleLane(context.Background(), msg, "tenant-a"); err != nil {
			t.Fatal(err)
		}
	}
	if len(st.rows["tenant-a"]) != 1 || c.duplicateCount() != 2 || c.integrityStats().Stored != 1 {
		t.Fatalf("rows=%d duplicates=%d ledger=%+v, want one stored trap and two duplicates",
			len(st.rows["tenant-a"]), c.duplicateCount(), c.integrityStats())
	}
}

func TestDeviceTrapConsumerBoundsAndMalformed(t *testing.T) {
	st := newMemTrapStore()
	c := NewDeviceTrapConsumer(nil, st, nil)
	ctx := context.Background()
	if err := c.handleLane(ctx, bus.Message{Value: []byte{0xff, 0x01}}, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err := c.handleLane(ctx, trapMsg(t), "tenant-a"); err != nil {
		t.Fatal(err)
	}
	var many []*devicev1.DeviceTrapEvent
	for i := 0; i <= device.MaxTrapEventsPerBatch; i++ {
		many = append(many, trapEvent("tenant-a", "agent-a", "fp"))
	}
	if err := c.handleLane(ctx, trapMsg(t, many...), "tenant-a"); err != nil {
		t.Fatal(err)
	}
	bad := trapEvent("tenant-a", "agent-a", "fp-bad")
	bad.Version = "snmpv9"
	good := trapEvent("tenant-a", "agent-a", "fp-good")
	if err := c.handleLane(ctx, trapMsg(t, bad, good), "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if s := c.integrityStats(); s.Malformed != 4 || s.Stored != 1 {
		t.Fatalf("ledger = %+v, want four malformed and the one valid trap stored", s)
	}
	if rows := st.rows["tenant-a"]; len(rows) != 1 || rows[0].Fingerprint != "fp-good" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestDeviceTrapConsumerRefusesAckOnPersistFailure(t *testing.T) {
	st := newMemTrapStore()
	st.failErr = errors.New("postgres unavailable")
	c := NewDeviceTrapConsumer(nil, st, nil)
	if err := c.handleLane(context.Background(), trapMsg(t, trapEvent("tenant-a", "agent-a", "fp")), "tenant-a"); err == nil {
		t.Fatal("a persistence failure was acked; the bus would never redeliver the trap")
	}
}

func TestDeviceTrapConsumerClampsFutureDeviceClock(t *testing.T) {
	st := newMemTrapStore()
	c := NewDeviceTrapConsumer(nil, st, nil)
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	c.clock = func() time.Time { return now }
	e := trapEvent("tenant-a", "agent-a", "fp")
	e.ObservedAtUnixNano = now.Add(48 * time.Hour).UnixNano()
	if err := c.handleLane(context.Background(), trapMsg(t, e), "tenant-a"); err != nil {
		t.Fatal(err)
	}
	rec := st.rows["tenant-a"][0]
	if !rec.ReceivedAt.Equal(now) || rec.ObservedAt.After(now.Add(time.Hour)) {
		t.Fatalf("observed=%s received=%s, want the device's future clock clamped", rec.ObservedAt, rec.ReceivedAt)
	}
}
