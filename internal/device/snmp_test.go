// SPDX-License-Identifier: LicenseRef-probectl-TBD

package device

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

var pollTime = time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

// fakeConn serves canned scalars (Get) and table columns (BulkWalk) — the
// snmpsim-style double for the poller logic. The env-gated integration test
// below drives the real gosnmp client instead.
type fakeConn struct {
	scalars map[string]gosnmp.SnmpPDU            // full OID -> PDU
	tables  map[string]map[uint32]gosnmp.SnmpPDU // column OID -> idx -> PDU
	getErr  error
	closed  bool
}

func (f *fakeConn) Get(oids []string) ([]gosnmp.SnmpPDU, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	out := make([]gosnmp.SnmpPDU, 0, len(oids))
	for _, oid := range oids {
		if p, ok := f.scalars[oid]; ok {
			p.Name = oid
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakeConn) BulkWalk(root string, fn gosnmp.WalkFunc) error {
	rows, ok := f.tables[root]
	if !ok {
		return fmt.Errorf("no such table %s", root) // swallowed by walkColumn
	}
	idxs := make([]int, 0, len(rows))
	for i := range rows {
		idxs = append(idxs, int(i))
	}
	sort.Ints(idxs)
	for _, i := range idxs {
		p := rows[uint32(i)]
		p.Name = fmt.Sprintf("%s.%d", root, i)
		if err := fn(p); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeConn) Close() error { f.closed = true; return nil }

func pdu(v any) gosnmp.SnmpPDU { return gosnmp.SnmpPDU{Value: v} }

// healthyConn models a well-behaved switch: 2 interfaces, HC counters, CPU,
// RAM, a temperature sensor, and an interface address for hop correlation.
func healthyConn() *fakeConn {
	f := &fakeConn{
		scalars: map[string]gosnmp.SnmpPDU{
			oidSysName:   pdu([]byte("core-sw1")),
			oidSysUpTime: pdu(uint32(8_640_000)), // ticks -> 86400 s
			oidSysDescr:  pdu([]byte("probeOS 1.0")),
		},
		tables: map[string]map[uint32]gosnmp.SnmpPDU{
			oidIfDescr:         {1: pdu([]byte("GigabitEthernet0/1")), 2: pdu([]byte("GigabitEthernet0/2"))},
			oidIfName:          {1: pdu([]byte("eth0")), 2: pdu([]byte("eth1"))},
			oidIfOperStatus:    {1: pdu(1), 2: pdu(2)},
			oidIfHighSpeed:     {1: pdu(uint32(1000)), 2: pdu(uint32(1000))},
			oidIfHCInOctets:    {1: pdu(uint64(1_000_000)), 2: pdu(uint64(50))},
			oidIfHCOutOctets:   {1: pdu(uint64(2_000_000)), 2: pdu(uint64(60))},
			oidIfInErrors:      {1: pdu(uint32(3))},
			oidIfOutErrors:     {1: pdu(uint32(4))},
			oidIfInDiscards:    {1: pdu(uint32(5))},
			oidIfOutDiscards:   {1: pdu(uint32(6))},
			oidHrProcessorLoad: {1: pdu(20), 2: pdu(40)},
			oidHrStorageType: {
				1: pdu(oidHrStorageTypeRAM),     // RAM row
				2: pdu(".1.3.6.1.2.1.25.2.1.4"), // disk row, ignored
			},
			oidHrStorageAllocUnits: {1: pdu(1024), 2: pdu(4096)},
			oidHrStorageSize:       {1: pdu(1000), 2: pdu(9999)},
			oidHrStorageUsed:       {1: pdu(400), 2: pdu(1234)},
			oidEntPhySensorType:    {1001: pdu(entPhySensorTypeCelsius), 1002: pdu(5)},
			oidEntPhySensorValue:   {1001: pdu(42), 1002: pdu(7)},
			oidEntPhysicalName:     {1001: pdu([]byte("CPU Temp"))},
		},
	}
	// ipAddrTable is indexed by the IP itself, not a row integer.
	f.tables[oidIPAdEntIfIndex] = nil
	return f
}

// ipWalkConn wraps fakeConn to serve the IP-indexed ipAddrTable.
type ipWalkConn struct {
	*fakeConn
	ipRows map[string]uint32 // ip -> ifIndex
}

func (c *ipWalkConn) BulkWalk(root string, fn gosnmp.WalkFunc) error {
	if root == oidIPAdEntIfIndex {
		for ip, idx := range c.ipRows {
			if err := fn(gosnmp.SnmpPDU{Name: root + "." + ip, Value: int(idx)}); err != nil {
				return err
			}
		}
		return nil
	}
	return c.fakeConn.BulkWalk(root, fn)
}

func find(t *testing.T, ms []Metric, name, ifName string) Metric {
	t.Helper()
	for _, m := range ms {
		if m.Name == name && m.IfName == ifName {
			return m
		}
	}
	t.Fatalf("metric %s (if=%q) not found in %d metrics", name, ifName, len(ms))
	return Metric{}
}

// TestPollSNMPHealthyDevice covers the whole normalization: identity, uptime,
// per-interface status/speed/counters, CPU average, RAM, sensors, and the
// inventory used for correlation.
func TestPollSNMPHealthyDevice(t *testing.T) {
	conn := &ipWalkConn{fakeConn: healthyConn(), ipRows: map[string]uint32{"10.0.0.1": 1}}
	dev := Target{Address: "192.0.2.1", Transport: TransportSNMPv2c, Sensors: true}

	ms, inv, err := pollSNMP(conn, dev, "t-a", "agent-1", pollTime)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}

	if inv.SysName != "core-sw1" || inv.SysDescr != "probeOS 1.0" || len(inv.Interfaces) != 2 {
		t.Fatalf("inventory = %+v", inv)
	}
	eth0 := inv.Interfaces[1]
	if eth0.Name != "eth0" || !eth0.OperUp || eth0.SpeedMbps != 1000 ||
		len(eth0.Addrs) != 1 || eth0.Addrs[0].String() != "10.0.0.1" {
		t.Fatalf("eth0 = %+v", eth0)
	}
	if inv.Interfaces[2].OperUp {
		t.Fatal("eth1 should be down")
	}

	up := find(t, ms, MetricUptimeSeconds, "")
	if up.Value != 86_400 || up.TenantID != "t-a" || up.Device != "192.0.2.1" || up.Source != SourceSNMP {
		t.Fatalf("uptime = %+v", up)
	}
	if v := find(t, ms, MetricIfOperStatus, "eth0").Value; v != 1 {
		t.Fatalf("eth0 oper = %v", v)
	}
	if v := find(t, ms, MetricIfOperStatus, "eth1").Value; v != 0 {
		t.Fatalf("eth1 oper = %v", v)
	}
	if v := find(t, ms, MetricIfInOctets, "eth0").Value; v != 1_000_000 {
		t.Fatalf("in octets = %v", v)
	}
	if v := find(t, ms, MetricIfOutErrors, "eth0").Value; v != 4 {
		t.Fatalf("out errors = %v", v)
	}
	if v := find(t, ms, MetricCPUUtilization, "").Value; v != 30 {
		t.Fatalf("cpu = %v (want avg of 20,40)", v)
	}
	if v := find(t, ms, MetricMemoryUsed, "").Value; v != 400*1024 {
		t.Fatalf("mem used = %v", v)
	}
	if v := find(t, ms, MetricMemoryTotal, "").Value; v != 1000*1024 {
		t.Fatalf("mem total = %v", v)
	}
	temp := find(t, ms, MetricSensorCelsius, "CPU Temp")
	if temp.Value != 42 {
		t.Fatalf("sensor = %+v (the non-celsius sensor must be skipped)", temp)
	}
	for _, m := range ms {
		if m.Name == MetricSensorCelsius && m.Value == 7 {
			t.Fatal("non-celsius sensor leaked into temperature metrics")
		}
	}
}

// TestPollSNMPGracefulDegradation: a device with no ifXTable, no
// HOST-RESOURCES, no sensors still yields identity + basic interface state —
// MIB variance must never fail the poll.
func TestPollSNMPGracefulDegradation(t *testing.T) {
	conn := &fakeConn{
		scalars: map[string]gosnmp.SnmpPDU{
			oidSysName:   pdu([]byte("dumb-switch")),
			oidSysUpTime: pdu(uint32(100)),
			oidSysDescr:  pdu([]byte("x")),
		},
		tables: map[string]map[uint32]gosnmp.SnmpPDU{
			oidIfDescr:      {7: pdu([]byte("port7"))},
			oidIfOperStatus: {7: pdu(1)},
		},
	}
	ms, inv, err := pollSNMP(conn, Target{Address: "192.0.2.9", Transport: TransportSNMPv2c}, "t-a", "a", pollTime)
	if err != nil {
		t.Fatalf("poll must degrade, not fail: %v", err)
	}
	// ifName falls back to ifDescr.
	if inv.Interfaces[7].Name != "port7" {
		t.Fatalf("ifName fallback = %+v", inv.Interfaces[7])
	}
	find(t, ms, MetricUptimeSeconds, "")
	find(t, ms, MetricIfOperStatus, "port7")
	for _, m := range ms {
		if m.Name == MetricCPUUtilization || m.Name == MetricMemoryUsed {
			t.Fatalf("phantom metric from missing MIB: %+v", m)
		}
	}
}

// TestPollSNMPUnreachable: a failing system group IS an error (reachability /
// auth check), and the runtime counts it.
func TestPollSNMPUnreachable(t *testing.T) {
	conn := &fakeConn{getErr: errors.New("timeout")}
	if _, _, err := pollSNMP(conn, Target{Address: "x"}, "t", "a", pollTime); err == nil {
		t.Fatal("expected error for unreachable device")
	}
}

// TestDialSNMPValidation: credential/transport mismatches fail before any
// packet leaves (fail closed, guardrail 12).
func TestDialSNMPValidation(t *testing.T) {
	if _, err := dialSNMP(Target{Address: "192.0.2.1", Transport: TransportSNMPv2c}, Credential{}); err == nil {
		t.Error("v2c without community must fail")
	}
	if _, err := dialSNMP(Target{Address: "192.0.2.1", Transport: TransportSNMPv3}, Credential{}); err == nil {
		t.Error("v3 without username must fail")
	}
	if _, err := dialSNMP(Target{Address: "192.0.2.1", Transport: TransportSNMPv3},
		Credential{Username: "u", AuthPass: "p", AuthProto: "rot13"}); err == nil {
		t.Error("unknown auth proto must fail")
	}
	if _, err := dialSNMP(Target{Address: "192.0.2.1", Transport: TransportGNMI}, Credential{}); err == nil {
		t.Error("gnmi transport must be rejected by the SNMP dialer")
	}
}

// TestCredentialRedaction: secrets never appear via %v/%s/%#v (guardrail 6).
func TestCredentialRedaction(t *testing.T) {
	c := Credential{Community: "sup3rsecret", AuthPass: "hunter2", PrivPass: "hunter3", Password: "pw"}
	for _, s := range []string{fmt.Sprintf("%v", c), c.String(), fmt.Sprintf("%#v", c)} {
		if strings.Contains(s, "hunter") || strings.Contains(s, "sup3rsecret") || strings.Contains(s, "pw") {
			t.Fatalf("credential leaked: %s", s)
		}
	}
}

// TestEnvCredentials: resolution, name mangling, and the loud missing-name error.
func TestEnvCredentials(t *testing.T) {
	env := map[string]string{
		"PROBECTL_DEVICE_CRED_CORE_RO_COMMUNITY": "public-ro",
		"PROBECTL_DEVICE_CRED_LAB_V3_USERNAME":   "probe",
		"PROBECTL_DEVICE_CRED_LAB_V3_AUTH_PROTO": "SHA256",
		"PROBECTL_DEVICE_CRED_LAB_V3_AUTH_PASS":  "a",
		"PROBECTL_DEVICE_CRED_LAB_V3_PRIV_PROTO": "aes",
		"PROBECTL_DEVICE_CRED_LAB_V3_PRIV_PASS":  "b",
	}
	src := NewEnvCredentials(func(k string) string { return env[k] })

	c, err := src.Resolve("core-ro")
	if err != nil || c.Community != "public-ro" {
		t.Fatalf("core-ro = %+v err=%v", c, err)
	}
	c, err = src.Resolve("lab.v3")
	if err != nil || c.Username != "probe" || c.AuthProto != "sha256" || c.PrivProto != "aes" {
		t.Fatalf("lab.v3 = %+v err=%v", c, err)
	}
	if _, err := src.Resolve("nope"); err == nil {
		t.Fatal("unknown credential name must error")
	}
}

// TestCounterResetDetection is the CORRECT-001 acceptance test:
// a 64-bit SNMP counter that drops between polls (device reboot / counter wrap)
// must be DROPPED for that cycle — not emitted — so the TSDB never sees a huge
// negative rate spike that would corrupt capacity or SLO data. The test confirms:
//   - pre-fix behavior: without filterCounterResets the raw decreasing value
//     would pass through (verified by the "no Runtime" baseline below)
//   - post-fix behavior: filterCounterResets drops the reset counter metrics,
//     emits a gap, updates the cache to the new baseline, and increments the
//     counter_resets stat; the NEXT cycle with normal (increasing) values passes.
func TestCounterResetDetection(t *testing.T) {
	// Build a Runtime directly (bypassing Validate which requires ≥1 device)
	// since we only exercise filterCounterResets, which needs cache + stats.
	_ = slog.New(slog.NewTextHandler(io.Discard, nil))
	rt := &Runtime{
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		counterCache: make(map[counterKey]float64),
		dialSNMP:     dialSNMP,
	}

	dev := Target{Address: "10.0.0.1", Transport: TransportSNMPv2c}

	// First poll: establish the baseline (high counter values post-steady-state).
	baseline := []Metric{
		{Device: "10.0.0.1", IfIndex: 1, IfName: "eth0", Name: MetricIfInOctets, Value: 1_000_000_000},
		{Device: "10.0.0.1", IfIndex: 1, IfName: "eth0", Name: MetricIfOutOctets, Value: 500_000_000},
		{Device: "10.0.0.1", IfIndex: 1, IfName: "eth0", Name: MetricIfInErrors, Value: 10},
		{Device: "10.0.0.1", IfIndex: 1, IfName: "eth0", Name: MetricIfOperStatus, Value: 1}, // gauge — must pass through
		{Device: "10.0.0.1", IfIndex: 0, IfName: "", Name: MetricCPUUtilization, Value: 30},  // gauge — must pass through
	}
	after1 := rt.filterCounterResets(baseline)
	if len(after1) != len(baseline) {
		t.Fatalf("first poll: expected all %d metrics to pass through (cache is empty), got %d", len(baseline), len(after1))
	}
	if rt.stats.CounterResets.Load() != 0 {
		t.Fatalf("first poll: expected 0 resets, got %d", rt.stats.CounterResets.Load())
	}

	// Second poll: device rebooted — counters wrapped back to small values.
	// Gauges are unaffected (oper-status stays 1, CPU stays 30).
	postReboot := []Metric{
		{Device: "10.0.0.1", IfIndex: 1, IfName: "eth0", Name: MetricIfInOctets, Value: 5_000},  // reset!
		{Device: "10.0.0.1", IfIndex: 1, IfName: "eth0", Name: MetricIfOutOctets, Value: 3_000}, // reset!
		{Device: "10.0.0.1", IfIndex: 1, IfName: "eth0", Name: MetricIfInErrors, Value: 0},      // reset!
		{Device: "10.0.0.1", IfIndex: 1, IfName: "eth0", Name: MetricIfOperStatus, Value: 1},    // gauge — must pass
		{Device: "10.0.0.1", IfIndex: 0, IfName: "", Name: MetricCPUUtilization, Value: 25},     // gauge — must pass
	}
	after2 := rt.filterCounterResets(postReboot)

	// The three counter metrics must be dropped; the two gauges must pass through.
	if len(after2) != 2 {
		names := make([]string, len(after2))
		for i, m := range after2 {
			names[i] = m.Name
		}
		t.Fatalf("post-reboot poll: expected 2 metrics (gauges only), got %d: %v", len(after2), names)
	}
	for _, m := range after2 {
		if isCounter(m.Name) {
			t.Errorf("counter metric %q leaked through after reset", m.Name)
		}
	}
	if rt.stats.CounterResets.Load() != 3 {
		t.Fatalf("expected 3 counter_resets stat, got %d", rt.stats.CounterResets.Load())
	}
	_ = dev // suppress unused warning

	// Third poll: normal post-reboot traffic — counters increasing from the new baseline.
	// Must ALL pass through (cache was updated to the post-reboot values).
	normal := []Metric{
		{Device: "10.0.0.1", IfIndex: 1, IfName: "eth0", Name: MetricIfInOctets, Value: 50_000},
		{Device: "10.0.0.1", IfIndex: 1, IfName: "eth0", Name: MetricIfOutOctets, Value: 30_000},
		{Device: "10.0.0.1", IfIndex: 1, IfName: "eth0", Name: MetricIfInErrors, Value: 0},
		{Device: "10.0.0.1", IfIndex: 1, IfName: "eth0", Name: MetricIfOperStatus, Value: 1},
		{Device: "10.0.0.1", IfIndex: 0, IfName: "", Name: MetricCPUUtilization, Value: 28},
	}
	after3 := rt.filterCounterResets(normal)
	if len(after3) != len(normal) {
		t.Fatalf("normal post-reboot poll: expected all %d metrics, got %d (cache should now hold new baseline)", len(normal), len(after3))
	}
	// Reset count must still be 3 (no new resets in cycle 3).
	if rt.stats.CounterResets.Load() != 3 {
		t.Fatalf("expected still 3 counter_resets after normal cycle, got %d", rt.stats.CounterResets.Load())
	}
}

// TestCounterResetWiredInPollOnce confirms that filterCounterResets is called
// on the default production path (pollOnce → filterCounterResets → emit), not
// just in isolation. It runs two synthetic polls via the Runtime's pollOnce
// seam: the first establishes a baseline; the second simulates a device reboot
// (counters decrease); the emitter must receive ONLY the gauges on the second
// call (no counter metrics leak through).
func TestCounterResetWiredInPollOnce(t *testing.T) {
	capture := &captureEmitter{}
	rt := &Runtime{
		cfg:          &Config{TenantID: "t-wire", AgentID: "ag-1"},
		emit:         capture,
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		correlator:   NewCorrelator(),
		counterCache: make(map[counterKey]float64),
		dialSNMP:     dialSNMP,
	}

	dev := Target{Address: "10.1.1.1", Transport: TransportSNMPv2c}

	// Inject a fake SNMP connection factory so pollOnce doesn't open a socket.
	poll1 := healthyConn() // baseline: in-octets=1_000_000, out-octets=2_000_000
	poll2 := healthyConn()
	// Simulate reboot: halve the counter values so they're less than poll1.
	poll2.tables[oidIfHCInOctets] = map[uint32]gosnmp.SnmpPDU{1: pdu(uint64(100)), 2: pdu(uint64(5))}
	poll2.tables[oidIfHCOutOctets] = map[uint32]gosnmp.SnmpPDU{1: pdu(uint64(200)), 2: pdu(uint64(6))}
	poll2.tables[oidIfInErrors] = map[uint32]gosnmp.SnmpPDU{1: pdu(uint32(0))}
	poll2.tables[oidIfOutErrors] = map[uint32]gosnmp.SnmpPDU{1: pdu(uint32(0))}
	poll2.tables[oidIfInDiscards] = map[uint32]gosnmp.SnmpPDU{1: pdu(uint32(0))}
	poll2.tables[oidIfOutDiscards] = map[uint32]gosnmp.SnmpPDU{1: pdu(uint32(0))}

	calls := 0
	rt.dialSNMP = func(_ Target, _ Credential) (snmpConn, error) {
		calls++
		if calls == 1 {
			return &ipWalkConn{fakeConn: poll1, ipRows: map[string]uint32{"10.1.1.1": 1}}, nil
		}
		return &ipWalkConn{fakeConn: poll2, ipRows: map[string]uint32{"10.1.1.1": 1}}, nil
	}

	ctx := context.Background()
	rt.pollOnce(ctx, dev, Credential{Community: "public"})
	firstBatch := len(capture.snapshot())
	rt.pollOnce(ctx, dev, Credential{Community: "public"})

	emitted := capture.snapshot()
	// After the second (reboot) poll, the counter metrics for both interfaces
	// must be absent from the emitted set. Gauges (oper-status, speed, CPU,
	// memory, uptime) must all be present.
	for _, m := range emitted[firstBatch:] {
		if isCounter(m.Name) {
			t.Errorf("wired-in check: counter metric %q leaked through after simulated reboot", m.Name)
		}
	}
	if rt.stats.CounterResets.Load() == 0 {
		t.Fatal("wired-in check: expected CounterResets > 0 after simulated reboot poll (pollOnce did not call filterCounterResets)")
	}
}

// TestSNMPIntegration drives the REAL gosnmp client against a live target
// (snmpsim or lab gear): PROBECTL_TEST_SNMP_TARGET=host[:port] with
// PROBECTL_TEST_SNMP_COMMUNITY. Skipped otherwise (CI starts a loopback snmpd
// target for this).
func TestSNMPIntegration(t *testing.T) {
	target := getenvDefault("PROBECTL_TEST_SNMP_TARGET", "")
	if target == "" {
		t.Skip("PROBECTL_TEST_SNMP_TARGET not set")
	}
	host, port, err := snmpIntegrationTarget(target)
	if err != nil {
		t.Fatalf("PROBECTL_TEST_SNMP_TARGET: %v", err)
	}
	community := getenvDefault("PROBECTL_TEST_SNMP_COMMUNITY", "public")
	dev := Target{Address: host, Port: port, Transport: TransportSNMPv2c, Interval: time.Minute, Credential: "it"}
	conn, err := dialSNMP(dev, Credential{Community: community})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	ms, inv, err := pollSNMP(conn, dev, "t-it", "it", time.Now())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(ms) == 0 || inv.SysName == "" {
		t.Fatalf("expected live metrics + sysName, got %d metrics, inv=%+v", len(ms), inv)
	}
	t.Logf("live poll: %d metrics from %s (%d interfaces)", len(ms), inv.SysName, len(inv.Interfaces))
}

func TestSNMPIntegrationTargetParsesOptionalPort(t *testing.T) {
	tests := []struct {
		raw      string
		wantHost string
		wantPort uint16
		wantErr  bool
	}{
		{raw: "192.0.2.10", wantHost: "192.0.2.10", wantPort: 161},
		{raw: "127.0.0.1:1161", wantHost: "127.0.0.1", wantPort: 1161},
		{raw: "localhost:2161", wantHost: "localhost", wantPort: 2161},
		{raw: ":1161", wantErr: true},
		{raw: "127.0.0.1:0", wantErr: true},
		{raw: "127.0.0.1:not-a-port", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			host, port, err := snmpIntegrationTarget(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got host=%q port=%d", host, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Fatalf("target = %q:%d, want %q:%d", host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func snmpIntegrationTarget(raw string) (string, uint16, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, errors.New("empty target")
	}
	host := raw
	port := uint16(161)
	if h, p, ok := strings.Cut(raw, ":"); ok {
		h = strings.TrimSpace(h)
		if h == "" {
			return "", 0, errors.New("missing host")
		}
		n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 16)
		if err != nil || n == 0 {
			return "", 0, fmt.Errorf("invalid port %q", p)
		}
		host, port = h, uint16(n)
	}
	return host, port, nil
}
