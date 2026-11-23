// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
)

func TestDeviceInventoryReferencesKeepIndependentSources(t *testing.T) {
	dir := t.TempDir()
	save := func(name string, content []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	const feed = `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"format":"NVD_CVE","version":"2.0","timestamp":"2026-10-21T18:40:00.000","vulnerabilities":[]}`
	const bindings = `{"version":1,"bindings":[{"manufacturer":"Example Networks","model":"XR-1","version_field":"firmware","cpe_part":"o","cpe_vendor":"reviewed","cpe_product":"owned-firmware","version_order":"exact_only"}]}`
	const lifecycle = `{"version":1,"observed_at":"2026-10-21","records":[{"manufacturer":"Example Networks","model":"XR-1","notice_url":"https://equipment.example.invalid/notices/xr1","notice_published_at":"2026-08-01","end_of_support":"2029-09-10"}]}`
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	if _, err := gzipWriter.Write([]byte(feed)); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	metadata := func(content string) []byte {
		return fmt.Appendf(nil, "lastModifiedDate:2026-10-21T18:45:00Z\nsize:%d\nsha256:%x\n", len(content), crypto.Hash([]byte(content)))
	}
	files := DeviceInventoryReferenceFiles{
		Lifecycle: save("lifecycle.json", []byte(lifecycle)), KEV: filepath.Join(dir, "missing-kev.json"),
		NVD: save("nvd.json.gz", compressed.Bytes()), NVDMetadata: save("nvd.meta", metadata(feed)),
		CPEBindings: save("bindings.json", []byte(bindings)),
	}
	now := time.Date(2026, time.October, 21, 20, 0, 0, 0, time.UTC)
	component := entity.SNMPPhysicalComponent{Manufacturer: "Example Networks", Model: "XR-1", Firmware: "8.1.4"}
	references, issues := LoadDeviceInventoryReferences(t.Context(), files)
	flags := references.Lookup(component, now, 24*time.Hour)
	if len(issues) != 1 || issues["kev"] == nil || flags.Lifecycle == nil || flags.VulnerabilityCoverage != "available" {
		t.Fatal("a missing catalog impaired a separately verified source", flags, issues)
	}

	files.NVDMetadata = save("nvd.meta", metadata(feed+" "))
	references, issues = LoadDeviceInventoryReferences(t.Context(), files)
	flags = references.Lookup(component, now, 24*time.Hour)
	if len(issues) != 2 || issues["nvd"] == nil || flags.Lifecycle == nil || flags.VulnerabilityCoverage != "unavailable" {
		t.Fatal("an unverifiable archive impaired lifecycle or entered lookup", flags, issues)
	}

	files.NVDMetadata = save("nvd.meta", metadata(feed))
	files.NVD = save("nvd.json.gz", compressed.Bytes()[:compressed.Len()-6])
	references, issues = LoadDeviceInventoryReferences(t.Context(), files)
	if flags = references.Lookup(component, now, 24*time.Hour); issues["nvd"] == nil || flags.VulnerabilityCoverage != "unavailable" {
		t.Fatal("a damaged gzip footer entered lookup", flags, issues)
	}

	references, issues = LoadDeviceInventoryReferences(t.Context(), DeviceInventoryReferenceFiles{})
	if flags = references.Lookup(component, now, 24*time.Hour); len(issues) != 0 || flags.Lifecycle != nil || flags.VulnerabilityCoverage != "unavailable" {
		t.Fatal("the default deployment assumed reference-data coverage", flags, issues)
	}
}
