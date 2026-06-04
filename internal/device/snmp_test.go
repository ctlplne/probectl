package device

import (
	"errors"
	"fmt"
	"sort"
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
	dev := DeviceConfig{Address: "192.0.2.1", Transport: TransportSNMPv2c, Sensors: true}

	ms, inv, err := pollSNMP(conn, dev, "t-a", "agent-1", pollTime)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}

	if inv.SysName != "core-sw1" || len(inv.Interfaces) != 2 {
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
	ms, inv, err := pollSNMP(conn, DeviceConfig{Address: "192.0.2.9", Transport: TransportSNMPv2c}, "t-a", "a", pollTime)
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
	if _, _, err := pollSNMP(conn, DeviceConfig{Address: "x"}, "t", "a", pollTime); err == nil {
		t.Fatal("expected error for unreachable device")
	}
}

// TestDialSNMPValidation: credential/transport mismatches fail before any
// packet leaves (fail closed, guardrail 12).
func TestDialSNMPValidation(t *testing.T) {
	if _, err := dialSNMP(DeviceConfig{Address: "192.0.2.1", Transport: TransportSNMPv2c}, Credential{}); err == nil {
		t.Error("v2c without community must fail")
	}
	if _, err := dialSNMP(DeviceConfig{Address: "192.0.2.1", Transport: TransportSNMPv3}, Credential{}); err == nil {
		t.Error("v3 without username must fail")
	}
	if _, err := dialSNMP(DeviceConfig{Address: "192.0.2.1", Transport: TransportSNMPv3},
		Credential{Username: "u", AuthPass: "p", AuthProto: "rot13"}); err == nil {
		t.Error("unknown auth proto must fail")
	}
	if _, err := dialSNMP(DeviceConfig{Address: "192.0.2.1", Transport: TransportGNMI}, Credential{}); err == nil {
		t.Error("gnmi transport must be rejected by the SNMP dialer")
	}
}

// TestCredentialRedaction: secrets never appear via %v/%s/%#v (guardrail 6).
func TestCredentialRedaction(t *testing.T) {
	c := Credential{Community: "sup3rsecret", AuthPass: "hunter2", PrivPass: "hunter3", Password: "pw"}
	for _, s := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%s", c), fmt.Sprintf("%#v", c)} {
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

// TestSNMPIntegration drives the REAL gosnmp client against a live target
// (snmpsim or lab gear): PROBECTL_TEST_SNMP_TARGET=host[:port] with
// PROBECTL_TEST_SNMP_COMMUNITY. Skipped otherwise (the CI compose stack wires
// snmpsim for this).
func TestSNMPIntegration(t *testing.T) {
	target := getenvDefault("PROBECTL_TEST_SNMP_TARGET", "")
	if target == "" {
		t.Skip("PROBECTL_TEST_SNMP_TARGET not set")
	}
	community := getenvDefault("PROBECTL_TEST_SNMP_COMMUNITY", "public")
	dev := DeviceConfig{Address: target, Port: 161, Transport: TransportSNMPv2c, Interval: time.Minute, Credential: "it"}
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
