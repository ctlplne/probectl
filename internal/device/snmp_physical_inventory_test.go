// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

type snmpPhysicalFixture struct {
	columns map[string][]gosnmp.SnmpPDU
	failOn  string
}

func (*snmpPhysicalFixture) Get([]string) ([]gosnmp.SnmpPDU, error) {
	return nil, errors.New("fixture accepts physical table walks")
}

func (*snmpPhysicalFixture) BulkWalk(_ string, _ gosnmp.WalkFunc) error {
	return errors.New("physical evidence requires complete response packets")
}

func (fixture *snmpPhysicalFixture) walkEvidenceColumn(_ context.Context, root string, visit gosnmp.WalkFunc) error {
	if root == fixture.failOn {
		return errors.New("fixture interrupted the physical table")
	}
	for _, pdu := range fixture.columns[root] {
		if err := visit(pdu); err != nil {
			return err
		}
	}
	return nil
}

func (*snmpPhysicalFixture) Close() error { return nil }

func TestSNMPPhysicalInventoryUsesOriginalEntityRow(t *testing.T) {
	integer := func(suffix, index string, value int) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: snmpEntityPhysical + suffix + "." + index, Type: gosnmp.Integer, Value: value}
	}
	text := func(suffix, index, value string) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: snmpEntityPhysical + suffix + "." + index, Type: gosnmp.OctetString, Value: []byte(value)}
	}
	mib := &snmpPhysicalFixture{columns: map[string][]gosnmp.SnmpPDU{
		snmpEntityClass:            {integer(".5", "12", 9), integer(".5", "4", 3), integer(".5", "27", 3)},
		snmpEntityPhysical + ".4":  {integer(".4", "4", 0), integer(".4", "12", 4)},
		snmpEntityPhysical + ".8":  {text(".8", "4", "B.01")},
		snmpEntityPhysical + ".9":  {text(".9", "12", "6.1a")},
		snmpEntityPhysical + ".10": {text(".10", "4", "2026.1"), text(".10", "999", "foreign")},
		snmpEntityPhysical + ".11": {text(".11", "4", "chassis-24"), text(".11", "12", "module-11")},
		snmpEntityPhysical + ".12": {text(".12", "4", "Example Networks")},
		snmpEntityPhysical + ".13": {text(".13", "12", "EX-MODULE"), text(".13", "4", "EX-CHASSIS")},
	}}
	result, err := pollSNMPPhysicalInventory(t.Context(), mib)
	if err != nil || len(result) != 3 {
		t.Fatal("incomplete original component population", result, err)
	}
	chassis, module, other := result[0], result[1], result[2]
	if chassis.Index != 4 || chassis.Class != 3 || chassis.Parent == nil || *chassis.Parent != 0 ||
		chassis.Model != "EX-CHASSIS" || chassis.Manufacturer != "Example Networks" ||
		chassis.Serial != "chassis-24" || chassis.Firmware != "" || chassis.Software != "2026.1" ||
		chassis.Hardware != "B.01" {
		t.Fatal("the chassis was enriched with data from another entity or lost an observed leaf", chassis)
	}
	if module.Index != 12 || module.Class != 9 || module.Parent == nil || *module.Parent != 4 ||
		module.Model != "EX-MODULE" || module.Serial != "module-11" || module.Firmware != "6.1a" ||
		module.Software != "" || other.Index != 27 || other.Parent != nil || other.Firmware != "" {
		t.Fatal("module or second chassis gained an unobserved inventory field", module, other)
	}
	originalFirmware := mib.columns[snmpEntityPhysical+".9"]
	mib.columns[snmpEntityPhysical+".9"] = append(append([]gosnmp.SnmpPDU(nil), originalFirmware...), text(".9", "27", "wrong\nfirmware"))
	if result, err := pollSNMPPhysicalInventory(t.Context(), mib); !errors.Is(err, errSNMPPhysicalInventory) || len(result) != 0 {
		t.Fatal("a malformed firmware value produced an apparently complete result", result, err)
	}
	mib.columns[snmpEntityPhysical+".9"] = originalFirmware
	mib.failOn = snmpEntityPhysical + ".13"
	if result, err := pollSNMPPhysicalInventory(t.Context(), mib); err == nil || len(result) != 0 {
		t.Fatal("a partial walk advanced inventory coverage", result, err)
	}
	mib.failOn = ""
	mib.columns[snmpEntityClass] = append(mib.columns[snmpEntityClass], integer(".5", "4", 9))
	if result, err := pollSNMPPhysicalInventory(t.Context(), mib); !errors.Is(err, errSNMPPhysicalInventory) || len(result) != 0 {
		t.Fatal("a conflicting duplicate entity class advanced inventory coverage", result, err)
	}
}

func TestSNMPPhysicalInventoryReadsPairedOwnedSimulators(t *testing.T) {
	const sourceDate = "2026-11-21"
	bindings, err := readDeviceCPEBindings(strings.NewReader(`{"version":1,"bindings":[{"manufacturer":"Example Networks","model":"EX-CHASSIS","version_field":"firmware","cpe_part":"o","cpe_vendor":"example_networks","cpe_product":"ex_os","version_order":"numeric_dot_equal_width"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := readDeviceLifecycleCatalog(strings.NewReader(`{"version":1,"observed_at":"2026-11-21","records":[{"manufacturer":"Example Networks","model":"EX-CHASSIS","notice_url":"https://equipment.example.invalid/notices/ex","notice_published_at":"2026-03-01","end_of_support":"2028-01-01"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	const feed = `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"format":"NVD_CVE","version":"2.0","timestamp":"2026-11-21T08:00:00Z","vulnerabilities":[{"cve":{"id":"CVE-2026-99101","vulnStatus":"Analyzed","published":"2026-10-01T00:00:00Z","lastModified":"2026-11-20T00:00:00Z","configurations":[{"operator":"OR","nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:o:example_networks:ex_os:*:*:*:*:*:*:*:*","versionStartIncluding":"1.2.0","versionEndExcluding":"1.3.0"}]}]}]}}]}`
	nvd, err := readDeviceNVDCatalog(t.Context(), strings.NewReader(feed), []nvdProductKey{{"o", "example_networks", "ex_os"}})
	if err != nil {
		t.Fatal(err)
	}
	kev, err := readDeviceKEVCatalog(strings.NewReader(`{"catalogVersion":"2026.11.21","dateReleased":"2026-11-21T09:00:00Z","count":1,"vulnerabilities":[{"cveID":"CVE-2026-99101","dateAdded":"2026-11-21","dueDate":"2026-12-04"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	references := &DeviceInventoryReferences{bindings: bindings, lifecycle: lifecycle, nvd: nvd, kev: kev}
	at := time.Date(2026, time.November, 21, 10, 0, 0, 0, time.UTC)
	integer := func(value int) gosnmp.SnmpPDU { return gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: value} }
	text := func(value string) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte(value)}
	}
	for lane, firmware := range []string{"1.2.3", "1.3.0"} {
		t.Run(firmware, func(t *testing.T) {
			serial := fmt.Sprintf("owned-chassis-%d", lane)
			port := serveSNMPVendorFixture(t, ".1.3.6.1.4.1.8072.3.2.10", &fakeConn{tables: map[string]map[uint32]gosnmp.SnmpPDU{
				snmpEntityClass:            {4: integer(3), 12: integer(9)},
				snmpEntityPhysical + ".4":  {4: integer(0), 12: integer(4)},
				snmpEntityPhysical + ".9":  {4: text(firmware), 12: text("same-module-version")},
				snmpEntityPhysical + ".11": {4: text(serial)},
				snmpEntityPhysical + ".12": {4: text("Example Networks"), 12: text("Example Networks")},
				snmpEntityPhysical + ".13": {4: text("EX-CHASSIS"), 12: text("EX-MODULE")},
			}})
			conn, err := dialSNMP(Target{Address: "127.0.0.1", Port: port, Transport: TransportSNMPv2c},
				Credential{Community: "owned-loopback-fixture"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			rows, err := pollSNMPPhysicalInventory(ctx, conn)
			if err != nil || len(rows) != 2 || rows[0].Serial != serial || rows[0].Firmware != firmware ||
				rows[0].Parent == nil || *rows[0].Parent != 0 || rows[1].Parent == nil || *rows[1].Parent != rows[0].Index ||
				rows[1].Model != "EX-MODULE" || rows[1].Serial != "" {
				t.Fatal("the wire snapshot lost an authenticated row or original parent and serial presence", rows, err)
			}
			flags := references.Lookup(rows[0], at, 24*time.Hour)
			if flags.Lifecycle == nil || flags.Lifecycle.ObservedAt != sourceDate ||
				flags.Lifecycle.Notice.EndOfSupport != "2028-01-01" || flags.VulnerabilityCoverage != "available" ||
				len(flags.Vulnerabilities) != 1-lane {
				t.Fatal("applicability or lifecycle evidence did not follow the original model and firmware", flags)
			}
			if lane == 0 && (flags.Vulnerabilities[0].ID != "CVE-2026-99101" ||
				flags.Vulnerabilities[0].KEVAdded != sourceDate || flags.Vulnerabilities[0].NVDObservedAt.IsZero()) {
				t.Fatal("the applicable version lost the source receipts", flags.Vulnerabilities[0])
			}
			module := references.Lookup(rows[1], at, 24*time.Hour)
			if module.Lifecycle != nil || module.VulnerabilityCoverage != "unavailable" || len(module.Vulnerabilities) != 0 {
				t.Fatal("a module inherited its chassis reference findings", module)
			}
			withoutFeeds := (*DeviceInventoryReferences)(nil).Lookup(rows[0], at, 24*time.Hour)
			if withoutFeeds.VulnerabilityCoverage != "unavailable" || len(withoutFeeds.Vulnerabilities) != 0 || withoutFeeds.Lifecycle != nil {
				t.Fatal("a deployment without local feeds reported covered inventory", withoutFeeds)
			}
		})
	}
}
