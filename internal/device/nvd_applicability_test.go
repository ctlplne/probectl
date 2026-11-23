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
)

func TestDeviceCVEApplicabilityRequiresExactProductAndOriginalVersion(t *testing.T) {
	criteria := nvdDeviceCriterion{
		Vulnerable: true, Criteria: "cpe:2.3:o:example_networks:example_os:*:*:*:*:*:*:*:*",
		VersionStartIncluding: "2.3.4", VersionEndExcluding: "2.5.0",
	}
	node := nvdDeviceNode{Operator: "OR", CPEMatch: []nvdDeviceCriterion{criteria}}
	write := deviceCPE{part: "o", vendor: "example_networks", product: "example_os", version: "2.3.4", numericOrder: true}
	if got := matchDeviceNVDNode(write, node); got != nvdMatches {
		t.Fatal("the exact included version was lost", got)
	}
	write.version = "2.5.0"
	if got := matchDeviceNVDNode(write, node); got != nvdNoMatch {
		t.Fatal("the excluded endpoint became affected", got)
	}
	write.version = "2.4R3"
	if got := matchDeviceNVDNode(write, node); got != nvdUnknown {
		t.Fatal("a different vendor version scheme gained applicability", got)
	}
	write.version, write.product = "2.3.4", "example_os_x"
	if got := matchDeviceNVDNode(write, node); got != nvdNoMatch {
		t.Fatal("a neighboring product acquired CVE evidence", got)
	}
	write.product, write.numericOrder = "example_os", false
	if got := matchDeviceNVDNode(write, node); got != nvdUnknown {
		t.Fatal("the matcher applied an unreviewed ordering", got)
	}
	write.numericOrder, node.Operator = true, "AND"
	if got := matchDeviceNVDNode(write, node); got != nvdUnknown {
		t.Fatal("an unproven multiproduct condition became valid evidence", got)
	}
}

func TestDeviceKEVSnapshotAddsOnlyFreshOriginalCVEID(t *testing.T) {
	const feed = `{"catalogVersion":"2026.11.20","dateReleased":"2026-11-20T21:11:00Z","count":1,
		"vulnerabilities":[{"cveID":"CVE-2099-10001","dateAdded":"2026-11-20","dueDate":"2026-12-14",
		"vendorProject":"Synthetic Networks","product":"Example Software"}]}`
	reader, err := readDeviceKEVCatalog(strings.NewReader(feed))
	if err != nil {
		t.Fatal(err)
	}
	check := time.Date(2026, 11, 21, 7, 0, 0, 0, time.UTC)
	if entry, found := reader.lookupApplicableCVE("CVE-2099-10001", check, 30*time.Hour); !found || entry.DateAdded != "2026-11-20" {
		t.Fatal("the verified original catalog entry was lost", entry)
	}
	if _, found := reader.lookupApplicableCVE("CVE-2099-10002", check, 30*time.Hour); found {
		t.Fatal("the catalog yielded a different CVE ID")
	}
	if _, found := reader.lookupApplicableCVE("CVE-2099-10001", check.Add(72*time.Hour), 30*time.Hour); found {
		t.Fatal("an expired source became current exploitation evidence")
	}
	if _, err := readDeviceKEVCatalog(strings.NewReader(strings.Replace(feed, `"count":1`, `"count":2`, 1))); err == nil {
		t.Fatal("a partial catalog passed its declared size")
	}
}
