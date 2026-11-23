// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

func TestInventoryReferenceFlagsRequireExactObservedProductAndVersion(t *testing.T) {
	const binding = `{"manufacturer":"Example Networks","model":"XR-1","version_field":"firmware","cpe_part":"o","cpe_vendor":"example_networks","cpe_product":"xr_1_os","version_order":"numeric_dot_equal_width"}`
	catalog, err := readDeviceCPEBindings(strings.NewReader(`{"version":1,"bindings":[` + binding + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readDeviceCPEBindings(strings.NewReader(`{"version":1,"bindings":[` + binding + `,` + binding + `]}`)); err == nil {
		t.Fatal("duplicate authority for the same version field was accepted")
	}
	now := time.Date(2026, time.November, 21, 14, 0, 0, 0, time.UTC)
	noticed := now.Add(-time.Hour)
	component := entity.SNMPPhysicalComponent{Index: 7, Class: 3, Manufacturer: "Example Networks", Model: "XR-1",
		Firmware: "8.1.4", Software: "7.9.4", Serial: "synthetic-chassis"}
	lifecycle := &deviceLifecycleCatalog{observedAt: noticed,
		byProduct: map[deviceLifecycleKey]deviceLifecycleRecord{
			{"Example Networks", "XR-1"}: {Manufacturer: "Example Networks", Model: "XR-1",
				NoticeURL: "https://equipment.example.invalid/notice/xr1", NoticePublishedAt: "2026-06-01",
				EndOfSale: "2026-09-01", EndOfSupport: "2027-06-01"},
		},
	}
	const claimed = "CVE-2026-99101"
	affected := &nvdDeviceCVE{ID: claimed, Published: "2026-10-01T10:00:00Z", LastModified: "2026-11-21T07:00:00Z",
		Configurations: []nvdDeviceConfiguration{{Nodes: []nvdDeviceNode{{Operator: "OR", CPEMatch: []nvdDeviceCriterion{{
			Vulnerable: true, Criteria: "cpe:2.3:o:example_networks:xr_1_os:*:*:*:*:*:*:*:*",
			VersionStartIncluding: "8.1.0", VersionEndExcluding: "8.2.0",
		}}}}}},
	}
	nvd := &deviceNVDCatalog{observedAt: noticed, byProduct: map[nvdProductKey][]*nvdDeviceCVE{
		{"o", "example_networks", "xr_1_os"}: {affected},
	}}
	kev := &deviceKEVCatalog{released: noticed, version: "2026.11.21",
		entries: map[string]deviceKEVRecord{
			claimed:          {ID: claimed, DateAdded: "2026-11-21", DueDate: "2026-12-04"},
			"CVE-2026-99102": {ID: "CVE-2026-99102", DateAdded: "2026-11-21", DueDate: "2026-12-04"},
		},
	}
	flags := inventoryReferenceFlags(component, catalog, lifecycle, nvd, kev, now, 24*time.Hour)
	if flags.VulnerabilityCoverage != "available" || flags.Lifecycle == nil ||
		flags.Lifecycle.Notice.EndOfSale != "2026-09-01" || flags.Lifecycle.Notice.EndOfSupport != "2027-06-01" ||
		len(flags.Vulnerabilities) != 1 || flags.Vulnerabilities[0].ID != claimed ||
		flags.Vulnerabilities[0].ObservedValue != component.Firmware || flags.Vulnerabilities[0].VersionField != "firmware" ||
		flags.Vulnerabilities[0].KEVAdded != "2026-11-21" || !flags.Vulnerabilities[0].KEVObservedAt.Equal(noticed) ||
		!flags.Vulnerabilities[0].NVDObservedAt.Equal(noticed) {
		t.Fatal("the exact component lost a source-bound flag or picked up a neighbor's version", flags)
	}
	component.Firmware, component.Software = "8.2.0", "8.1.4"
	flags = inventoryReferenceFlags(component, catalog, lifecycle, nvd, kev, now, 24*time.Hour)
	if flags.Lifecycle == nil || flags.VulnerabilityCoverage != "available" || len(flags.Vulnerabilities) != 0 {
		t.Fatal("an exclusive firmware version or unmapped software value gained a CVE flag", flags)
	}
	component.Model = "XR-1 Plus"
	flags = inventoryReferenceFlags(component, catalog, lifecycle, nvd, kev, now, 24*time.Hour)
	if flags.VulnerabilityCoverage != "unavailable" || flags.Lifecycle != nil || len(flags.Vulnerabilities) != 0 {
		t.Fatal("an unreviewed product inherited another product's flags", flags)
	}
	component.Model, component.Firmware = "XR-1", "8.1.4"
	flags = inventoryReferenceFlags(component, catalog, lifecycle, nil, kev, now, 24*time.Hour)
	if flags.VulnerabilityCoverage != "unavailable" || len(flags.Vulnerabilities) != 0 {
		t.Fatal("a standalone KEV record asserted product applicability", flags)
	}
}
