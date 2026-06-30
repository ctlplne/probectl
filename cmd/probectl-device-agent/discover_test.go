// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/device"
)

func TestRunDiscoverWritesReviewOnlyFixtureResult(t *testing.T) {
	dir := t.TempDir()
	job := filepath.Join(dir, "job.json")
	fixture := filepath.Join(dir, "fixture.json")
	out := filepath.Join(dir, "review.json")
	t.Setenv("PROBECTL_DEVICE_CRED_CORE_RO_COMMUNITY", "public")
	if err := os.WriteFile(job, []byte(`{
	  "id": "job-cli",
	  "tenant_id": "tenant-a",
	  "created_by": "netops@example.com",
	  "ranges": ["10.10.0.0/30"],
	  "max_hosts": 2,
	  "credentials": [{"tenant_id": "tenant-a", "name": "core-ro", "transport": "snmpv2c"}],
	  "classifier_rules": [{"role": "edge-router", "sys_name_contains": ["edge"], "confidence": 0.9}]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture, []byte(`{
	  "devices": [{
	    "address": "10.10.0.1",
	    "sys_name": "edge-r1",
	    "sys_descr": "router",
	    "interfaces": [{"index": 1, "name": "wan0", "oper_up": true, "addrs": ["10.10.0.1"]}]
	  }]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runDiscover([]string{"-job", job, "-fixture", fixture, "-out", out}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var result device.DiscoveryResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.TenantID != "tenant-a" || result.Status != device.DiscoveryStatusReviewRequired ||
		len(result.Devices) != 1 || result.Devices[0].ActivationState != device.ActivationPendingReview ||
		result.Devices[0].Role != "edge-router" {
		t.Fatalf("result = %+v", result)
	}
}
