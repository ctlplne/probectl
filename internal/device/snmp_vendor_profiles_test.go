// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestVendorProfileMatchesOIDArcsAndRefusesAmbiguity(t *testing.T) {
	profiles := []SNMPVendorProfile{
		{ID: "family", SysObjectID: ".1.3.6.1.4.1.32473.1", MatchSubtree: true},
		{ID: "exact", SysObjectID: ".1.3.6.1.4.1.32473.1.2"},
		{ID: "defined-platform", SysObjectID: ".1.3.6.1.4.1.32473.1.2", SysDescrPrefix: "Documented platform "},
		{ID: "ambiguous-a", SysObjectID: ".1.3.6.1.4.1.32473.1.7"},
		{ID: "ambiguous-b", SysObjectID: ".1.3.6.1.4.1.32473.1.7"},
	}
	for _, example := range []struct{ oid, description, id string }{
		{"1.3.6.1.4.1.32473.1.4", "", "family"},
		{".1.3.6.1.4.1.32473.1.2", "unrecognized product", "exact"},
		{".1.3.6.1.4.1.32473.1.2", "Documented platform 3.1", "defined-platform"},
		{".1.3.6.1.4.1.32473.1.7", "", ""},
		{".1.3.6.1.4.1.32473.11.2", "", ""},
		{".1.3.6.1.4.1.32473.01.2", "", ""},
		{".1.3.6.1.4.1.32473.1.4294967296", "", ""},
	} {
		got := selectSNMPVendorProfile(profiles, example.oid, example.description)
		if got == nil && example.id != "" || got != nil && got.ID != example.id {
			t.Fatalf("profile for %s %q = %+v, want %s", example.oid, example.description, got, example.id)
		}
	}
}

func TestVendorProfileReadsExactObjectsAndKeepsTypedTenantSamples(t *testing.T) {
	const cpuOID = ".1.3.6.1.4.1.32473.2.1.0"
	const fanOID = ".1.3.6.1.4.1.32473.2.2"
	profile := SNMPVendorProfile{
		ID: "test-profile", Vendor: "Fixture", Platform: "Test switch", SysObjectID: ".1.3.6.1.4.1.32473.1",
		Objects: []SNMPVendorObject{
			{MIB: "FIXTURE-MIB::cpuLoad", OID: cpuOID, Kind: "scalar", Syntax: "integer", Metric: MetricCPUUtilization, Unit: "percent"},
			{MIB: "FIXTURE-MIB::fanSpeed", OID: fanOID, Kind: "column", Syntax: "gauge32", Metric: "probectl.device.fan.speed.rpm", Unit: "rpm"},
		},
	}
	if err := validateSNMPVendorProfiles([]SNMPVendorProfile{profile}); err != nil {
		t.Fatal(err)
	}
	conn := &fakeConn{
		scalars: map[string]gosnmp.SnmpPDU{cpuOID: {Type: gosnmp.Integer, Value: 42}},
		tables: map[string]map[uint32]gosnmp.SnmpPDU{fanOID: {
			3: {Type: gosnmp.Gauge32, Value: uint32(2400)},
			4: {Type: gosnmp.Counter32, Value: uint32(1200)},
		}},
	}
	base := Metric{TenantID: "tenant-a", AgentID: "device-agent-a", Device: "192.0.2.17", Source: SourceSNMP, At: pollTime}
	got := readSNMPVendorProfile(t.Context(), conn, profile, base)
	if len(got) != 2 || got[0].Name != MetricCPUUtilization || got[0].Value != 42 ||
		got[1].Component != "3" || got[1].Value != 2400 || got[1].TenantID != base.TenantID || got[1].Device != base.Device {
		t.Fatal("valid readings lost their exact metric scope or admitted a wrongly typed value", got)
	}
	profile.Objects[1].Unit = "seconds"
	if err := validateSNMPVendorProfiles([]SNMPVendorProfile{profile}); err == nil {
		t.Fatal("profile load accepted a mismatched unit")
	}
}

func TestVendorProfileConfigurationBindsReadToCurrentSystemObjectID(t *testing.T) {
	const readOID = ".1.3.6.1.4.1.32473.9.1.0"
	const raw = `apiVersion: probectl.io/device-agent/v1
tenant_id: owned-tenant
devices:
  - address: 192.0.2.8
    transport: snmpv2c
    credential: owned-reference
    snmp_vendor_profile: test-platform
snmp_vendor_profiles:
  - id: test-platform
    vendor: Fixture
    platform: Fixture network appliance
    sys_object_id: .1.3.6.1.4.1.32473.1.8
    objects:
      - mib_object: FIXTURE-MIB::cpuUtilization
        oid: ` + readOID + `
        kind: scalar
        syntax: gauge32
        metric: probectl.device.cpu.utilization
        unit: percent
`
	cfg := Default()
	if err := decodeConfigYAML([]byte(raw), cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, example := range []struct {
		identity any
		wireType gosnmp.Asn1BER
		profile  string
		usage    float64
	}{
		{".1.3.6.1.4.1.32473.1.8", gosnmp.ObjectIdentifier, "test-platform", 55},
		{".1.3.6.1.4.1.32473.1.9", gosnmp.ObjectIdentifier, "", 30},
		{".1.3.6.1.4.1.32473.1.8", gosnmp.OctetString, "", 30},
	} {
		conn := healthyConn()
		conn.scalars[oidSysObjectID] = gosnmp.SnmpPDU{Type: example.wireType, Value: example.identity}
		conn.scalars[readOID] = gosnmp.SnmpPDU{Type: gosnmp.Gauge32, Value: uint32(55)}
		metrics, inv, err := pollSNMP(t.Context(), conn, cfg.Devices[0], cfg.TenantID, "owned-agent", pollTime)
		if err != nil || inv.VendorProfile != example.profile {
			t.Fatal("the configured profile accepted a different or unavailable device identity", inv.VendorProfile, err)
		}
		var cpu []Metric
		for _, metric := range metrics {
			if metric.Name == MetricCPUUtilization {
				cpu = append(cpu, metric)
			}
		}
		if len(cpu) != 1 || cpu[0].Value != example.usage || cpu[0].TenantID != cfg.TenantID {
			t.Fatal("the profile shadowed the standard read without a verified value", cpu)
		}
	}
}

type vendorCompoundFixture struct {
	*fakeConn
	root string
	rows []gosnmp.SnmpPDU
}

func (f vendorCompoundFixture) BulkWalk(root string, visit gosnmp.WalkFunc) error {
	if root != f.root {
		return f.fakeConn.BulkWalk(root, visit)
	}
	for _, row := range f.rows {
		if err := visit(row); err != nil {
			return err
		}
	}
	return nil
}

func TestVendorProfilePreservesCompoundIndexesAndRejectsPartialWalks(t *testing.T) {
	const root = ".1.3.6.1.4.1.32473.12.1.8"
	column := SNMPVendorObject{OID: root, Kind: "column", Syntax: "integer", Metric: MetricCPUUtilization, Unit: "percent"}
	base := Metric{TenantID: "fixture-owner"}
	conn := vendorCompoundFixture{root: root, rows: []gosnmp.SnmpPDU{
		{Name: root + ".9.1.0.0", Type: gosnmp.Integer, Value: 37},
		{Name: root + ".9.2.0.0", Type: gosnmp.Integer, Value: 23},
	}}
	got, visited := readSNMPVendorColumn(t.Context(), conn, column, base, 2)
	if len(got) != 2 || visited != 2 || got[0].Component != "9.1.0.0" || got[1].Component != "9.2.0.0" || got[1].TenantID != base.TenantID {
		t.Fatal("compound entity keys lost their original indices or tenant", got, visited)
	}
	if got, visited := readSNMPVendorColumn(t.Context(), conn, column, base, 1); got != nil || visited != 1 {
		t.Fatal("a partial column was accepted after the row limit", got, visited)
	}
	conn.rows[1].Name = root + "0.9.2.0.0"
	if got, visited := readSNMPVendorColumn(t.Context(), conn, column, base, 2); got != nil || visited != 2 {
		t.Fatal("a neighboring OID root was accepted as a compound row", got, visited)
	}
}
