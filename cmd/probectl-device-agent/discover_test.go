// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/device"
)

func TestRunDiscoverBoundsInputFiles(t *testing.T) {
	const maxBytes = 8 << 20
	const jobJSON = `{"id":"job-bound","tenant_id":"tenant-a","ranges":["10.10.0.1"],"max_hosts":1,"credentials":[{"tenant_id":"tenant-a","name":"core-ro","transport":"snmpv2c"}]}`
	const fixtureJSON = `{"devices":[{"address":"10.10.0.1"}]}`

	dir := t.TempDir()
	t.Setenv("PROBECTL_DEVICE_CRED_CORE_RO_COMMUNITY", "public")
	writeInput := func(name, data string, size int) string {
		t.Helper()
		path := filepath.Join(dir, name)
		body := data + strings.Repeat(" ", size-len(data))
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	exactJob := writeInput("job-exact.json", jobJSON, maxBytes)
	exactFixture := writeInput("fixture-exact.json", fixtureJSON, maxBytes)
	if err := runDiscover([]string{"-job", exactJob, "-fixture", exactFixture, "-out", filepath.Join(dir, "exact-result.json")}); err != nil {
		t.Fatalf("exact-limit inputs: %v", err)
	}

	tests := []struct {
		name    string
		job     string
		fixture string
	}{
		{
			name:    "job",
			job:     writeInput("job-oversize.json", jobJSON, maxBytes+1),
			fixture: exactFixture,
		},
		{
			name:    "fixture",
			job:     exactJob,
			fixture: writeInput("fixture-oversize.json", fixtureJSON, maxBytes+1),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runDiscover([]string{"-job", tt.job, "-fixture", tt.fixture, "-out", filepath.Join(dir, tt.name+"-result.json")})
			if err == nil {
				t.Fatal("one-byte-oversize input: expected error")
			}
			if !strings.Contains(err.Error(), "8388608-byte limit") {
				t.Fatalf("one-byte-oversize input error = %q, want byte-limit detail", err)
			}
		})
	}
}

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
