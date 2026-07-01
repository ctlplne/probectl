// SPDX-License-Identifier: LicenseRef-probectl-TBD

package device

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
)

func testInventory() Inventory {
	return Inventory{
		Device:  "192.0.2.1",
		SysName: "core-sw1",
		Interfaces: map[uint32]Interface{
			1: {Index: 1, Name: "eth0", OperUp: true, Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
			2: {Index: 2, Name: "eth1"},
		},
	}
}

// TestCorrelatorHopToInterface is the sprint's correlation test: a path hop's
// responder IP resolves to the device interface that answered it.
func TestCorrelatorHopToInterface(t *testing.T) {
	c := NewCorrelator()
	c.Update(testInventory())

	ref, ok := c.MatchHopIP("10.0.0.1")
	if !ok || ref.Device != "192.0.2.1" || ref.SysName != "core-sw1" || ref.IfIndex != 1 || ref.IfName != "eth0" {
		t.Fatalf("hop->iface = %+v ok=%v", ref, ok)
	}
	// The management address itself correlates at device level.
	ref, ok = c.MatchHopIP("192.0.2.1")
	if !ok || ref.Device != "192.0.2.1" || ref.IfIndex != 0 {
		t.Fatalf("hop->device = %+v ok=%v", ref, ok)
	}
	if _, ok := c.MatchHopIP("203.0.113.99"); ok {
		t.Fatal("unknown hop must not match")
	}
	if _, ok := c.MatchHopIP("not-an-ip"); ok {
		t.Fatal("garbage hop must not match")
	}
}

// TestCorrelatorFlowToInterface: a flow record's (exporter, ifIndex) resolves
// to the named interface — including when the exporter speaks from an
// interface address rather than the management address.
func TestCorrelatorFlowToInterface(t *testing.T) {
	c := NewCorrelator()
	c.Update(testInventory())

	ref, ok := c.MatchExporterInterface("192.0.2.1", 2)
	if !ok || ref.IfName != "eth1" {
		t.Fatalf("flow->iface = %+v ok=%v", ref, ok)
	}
	// Exporter source = interface address: falls back via the IP index.
	ref, ok = c.MatchExporterInterface("10.0.0.1", 1)
	if !ok || ref.IfName != "eth0" || ref.Device != "192.0.2.1" {
		t.Fatalf("flow via iface addr = %+v ok=%v", ref, ok)
	}
	// Known device, unknown ifIndex: device-level partial match, ok=false.
	ref, ok = c.MatchExporterInterface("192.0.2.1", 99)
	if ok || ref.Device != "192.0.2.1" {
		t.Fatalf("partial match = %+v ok=%v", ref, ok)
	}
}

// TestCorrelatorUpdateReplaces: a re-poll with changed addresses drops stale
// IP index entries (devices renumber).
func TestCorrelatorUpdateReplaces(t *testing.T) {
	c := NewCorrelator()
	c.Update(testInventory())

	inv := testInventory()
	inv.Interfaces[1] = Interface{Index: 1, Name: "eth0", Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}
	c.Update(inv)

	if _, ok := c.MatchHopIP("10.0.0.1"); ok {
		t.Fatal("stale interface address survived re-poll")
	}
	if ref, ok := c.MatchHopIP("10.0.0.2"); !ok || ref.IfName != "eth0" {
		t.Fatalf("new address = %+v ok=%v", ref, ok)
	}
	if c.Devices() != 1 {
		t.Fatalf("devices = %d", c.Devices())
	}
}

func TestCorrelatorPruneBeforeDropsStaleInventoryLabels(t *testing.T) {
	c := NewCorrelator()
	base := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	oldInv := testInventory()
	oldInv.Device = "192.0.2.10"
	oldInv.SysName = "old-core"
	oldInv.Interfaces[1] = Interface{Index: 1, Name: "old-eth0", Addrs: []netip.Addr{netip.MustParseAddr("10.0.10.1")}}
	freshInv := testInventory()
	freshInv.Device = "192.0.2.20"
	freshInv.SysName = "fresh-core"
	freshInv.Interfaces[1] = Interface{Index: 1, Name: "fresh-eth0", Addrs: []netip.Addr{netip.MustParseAddr("10.0.20.1")}}

	c.UpdateAt(oldInv, base)
	c.UpdateAt(freshInv, base.Add(48*time.Hour))

	if deleted := c.PruneBefore(base.Add(24 * time.Hour)); deleted != 1 {
		t.Fatalf("deleted = %d, want one stale device", deleted)
	}
	if ref, ok := c.MatchHopIP("10.0.10.1"); ok {
		t.Fatalf("stale hop still exposes old labels: %+v", ref)
	}
	if ref, ok := c.MatchExporterInterface("192.0.2.10", 1); ok || ref.Device != "" || ref.SysName != "" || ref.IfName != "" {
		t.Fatalf("stale exporter still exposes old labels: %+v ok=%v", ref, ok)
	}
	if ref, ok := c.MatchHopIP("10.0.20.1"); !ok || ref.SysName != "fresh-core" || ref.IfName != "fresh-eth0" {
		t.Fatalf("fresh hop label missing: %+v ok=%v", ref, ok)
	}
	if ref, ok := c.MatchExporterInterface("192.0.2.20", 1); !ok || ref.SysName != "fresh-core" || ref.IfName != "fresh-eth0" {
		t.Fatalf("fresh exporter label missing: %+v ok=%v", ref, ok)
	}
}

// stubConnDialer returns a canned conn for runtime tests.
func stubConnDialer(conn snmpConn, err error) func(Target, Credential) (snmpConn, error) {
	return func(Target, Credential) (snmpConn, error) { return conn, err }
}

type mapCreds map[string]Credential

func (m mapCreds) Resolve(name string) (Credential, error) {
	c, ok := m[name]
	if !ok {
		return Credential{}, errors.New("no such credential")
	}
	return c, nil
}

// TestRuntimePollOnce drives one SNMP cycle end to end: dial seam -> poll ->
// emit -> correlator update, plus the error counters.
func TestRuntimePollOnce(t *testing.T) {
	cfg := &Config{TenantID: "t-a", AgentID: "agent-1", Devices: []Target{{
		Address: "192.0.2.1", Transport: TransportSNMPv2c, Credential: "ro",
	}}}
	em := &captureEmitter{}
	rt, err := New(cfg, em, mapCreds{"ro": {Community: "public"}}, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	conn := &ipWalkConn{fakeConn: healthyConn(), ipRows: map[string]uint32{"10.0.0.1": 1}}
	rt.dialSNMP = stubConnDialer(conn, nil)

	rt.pollOnce(context.Background(), cfg.Devices[0], Credential{Community: "public"})

	if len(em.snapshot()) == 0 {
		t.Fatal("no metrics emitted")
	}
	if !conn.closed {
		t.Fatal("connection not closed after poll")
	}
	if ref, ok := rt.Correlator().MatchHopIP("10.0.0.1"); !ok || ref.IfName != "eth0" {
		t.Fatalf("correlator not updated: %+v ok=%v", ref, ok)
	}
	if s := rt.StatsSnapshot(); s["polls"] != 1 || s["metrics"] == 0 || s["poll_errors"] != 0 {
		t.Fatalf("stats = %+v", s)
	}

	// Dial failure path: counted, not fatal.
	rt.dialSNMP = stubConnDialer(nil, errors.New("refused"))
	rt.pollOnce(context.Background(), cfg.Devices[0], Credential{Community: "public"})
	if s := rt.StatsSnapshot(); s["poll_errors"] != 1 {
		t.Fatalf("stats after dial failure = %+v", s)
	}
}

// TestRuntimeUnknownCredentialFailsClosed: a typo'd credential name aborts Run
// before any polling starts.
func TestRuntimeUnknownCredentialFailsClosed(t *testing.T) {
	cfg := &Config{TenantID: "t", Devices: []Target{{
		Address: "192.0.2.1", Transport: TransportSNMPv2c, Credential: "typo",
	}}}
	rt, err := New(cfg, &captureEmitter{}, mapCreds{}, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := rt.Run(ctx); err == nil {
		t.Fatal("Run must fail closed on an unresolvable credential")
	}
}

// TestBusEmitterTenantTaggedBatch: metrics land on probectl.device.metrics,
// tenant-keyed, as a decodable DeviceMetricBatch.
func TestBusEmitterTenantTaggedBatch(t *testing.T) {
	b := bus.NewMemory()
	var got bus.Message
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = b.Subscribe(ctx, bus.DeviceMetricsTopic, "t", func(_ context.Context, m bus.Message) error {
			got = m
			close(done)
			return nil
		})
	}()
	time.Sleep(20 * time.Millisecond)

	em := NewBusEmitter(b, "t-a")
	if err := em.Emit(ctx, nil); err != nil {
		t.Fatalf("empty emit: %v", err)
	}
	ms := []Metric{{TenantID: "t-a", Device: "192.0.2.1", Name: MetricUptimeSeconds, Value: 42, At: pollTime}}
	if err := em.Emit(ctx, ms); err != nil {
		t.Fatalf("emit: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("nothing published")
	}
	if string(got.Key) != "t-a" {
		t.Fatalf("key = %q", got.Key)
	}
	var batch devicev1.DeviceMetricBatch
	if err := proto.Unmarshal(got.Value, &batch); err != nil || len(batch.Metrics) != 1 {
		t.Fatalf("batch = %+v err=%v", batch.Metrics, err)
	}
	if batch.Metrics[0].GetName() != MetricUptimeSeconds || batch.Metrics[0].GetValue() != 42 {
		t.Fatalf("metric = %+v", batch.Metrics[0])
	}
}

// TestConfigValidate covers transport defaults + the failure modes.
func TestConfigValidate(t *testing.T) {
	cfg := &Config{TenantID: "t", Devices: []Target{
		{Address: "a", Transport: TransportSNMPv2c, Credential: "c"},
		{Address: "b", Transport: TransportGNMI, Credential: "c"},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.Devices[0].Port != 161 || cfg.Devices[0].Interval != 60*time.Second {
		t.Fatalf("snmp defaults = %+v", cfg.Devices[0])
	}
	if cfg.Devices[1].Port != 9339 || len(cfg.Devices[1].GNMI.Paths) != 2 || cfg.Devices[1].GNMI.SampleInterval != 30*time.Second {
		t.Fatalf("gnmi defaults = %+v", cfg.Devices[1])
	}

	for name, bad := range map[string]*Config{
		"no tenant":     {Devices: []Target{{Address: "a", Transport: TransportSNMPv2c, Credential: "c"}}},
		"no devices":    {TenantID: "t"},
		"no address":    {TenantID: "t", Devices: []Target{{Transport: TransportSNMPv2c, Credential: "c"}}},
		"bad transport": {TenantID: "t", Devices: []Target{{Address: "a", Transport: "telnet", Credential: "c"}}},
		"no credential": {TenantID: "t", Devices: []Target{{Address: "a", Transport: TransportSNMPv2c}}},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

// TestConfigEnvQuickStart: the single-device env path builds a valid config.
func TestConfigEnvQuickStart(t *testing.T) {
	env := map[string]string{
		"PROBECTL_DEVICE_TENANT":                "t-env",
		"PROBECTL_DEVICE_BUS_MODE":              "kafka",
		"PROBECTL_DEVICE_BUS_BROKERS":           "k1:9092, k2:9092",
		"PROBECTL_DEVICE_TARGET":                "192.0.2.7",
		"PROBECTL_DEVICE_TRANSPORT":             "SNMPV3",
		"PROBECTL_DEVICE_CREDENTIAL":            "core",
		"PROBECTL_DEVICE_PORT":                  "1161",
		"PROBECTL_DEVICE_INTERVAL":              "30s",
		"PROBECTL_DEVICE_CORRELATION_RETENTION": "72h",
	}
	cfg := Default()
	cfg.applyEnv(func(k string) string { return env[k] })
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	d := cfg.Devices[0]
	if cfg.TenantID != "t-env" || d.Address != "192.0.2.7" || d.Transport != TransportSNMPv3 ||
		d.Port != 1161 || d.Interval != 30*time.Second || cfg.CorrelationRetention != 72*time.Hour || len(cfg.Bus.Brokers) != 2 {
		t.Fatalf("cfg = %+v dev = %+v", cfg, d)
	}
}
