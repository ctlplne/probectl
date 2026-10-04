// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/device"
)

// TestRunDiscoverImportApprovesReviewedCandidate drives the shipped
// `discover import` subcommand through the real device-agent dispatch (the same
// argument forwarding main() performs for `probectl-device-agent discover
// import ...`). It first runs `discover` to produce a review-only result, then
// imports an explicit reviewer approval and asserts the validated device target
// and the discovery.device_approved audit event are produced. Before the import
// subcommand existed this path was unreachable, so the happy-path case fails.
func TestRunDiscoverImportApprovesReviewedCandidate(t *testing.T) {
	dir := t.TempDir()
	job := filepath.Join(dir, "job.json")
	fixture := filepath.Join(dir, "fixture.json")
	resultPath := filepath.Join(dir, "result.json")
	t.Setenv("PROBECTL_DEVICE_CRED_CORE_RO_COMMUNITY", "public")

	if err := os.WriteFile(job, []byte(`{
	  "id": "job-import",
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

	// Produce the review-only discovery result the reviewer acts on.
	if err := runDiscover([]string{"-job", job, "-fixture", fixture, "-out", resultPath}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	var result device.DiscoveryResult
	raw, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Devices) != 1 {
		t.Fatalf("expected one discovered candidate, got %+v", result.Devices)
	}
	acceptedID := result.Devices[0].ID

	writeReview := func(name string, review device.DiscoveryReview) string {
		t.Helper()
		path := filepath.Join(dir, name)
		data, err := json.Marshal(review)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	tests := []struct {
		name    string
		review  device.DiscoveryReview
		wantErr string
	}{
		{
			name: "approves selected candidate",
			review: device.DiscoveryReview{
				TenantID:        "tenant-a",
				JobID:           "job-import",
				ReviewedBy:      "lead@example.com",
				AcceptDeviceIDs: []string{acceptedID},
			},
		},
		{
			name: "rejects cross-tenant review",
			review: device.DiscoveryReview{
				TenantID:        "tenant-b",
				JobID:           "job-import",
				ReviewedBy:      "lead@example.com",
				AcceptDeviceIDs: []string{acceptedID},
			},
			wantErr: "does not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reviewPath := writeReview(strings.ReplaceAll(tt.name, " ", "-")+".json", tt.review)
			out := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "-")+"-import.json")
			// Exactly what main()'s `case "discover"` forwards for
			// `probectl-device-agent discover import ...`.
			err := runDiscover([]string{"import", "-result", resultPath, "-review", reviewPath, "-out", out})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("import error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("discover import: %v", err)
			}

			var imported device.DiscoveryImport
			raw, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &imported); err != nil {
				t.Fatal(err)
			}
			if imported.TenantID != "tenant-a" || imported.JobID != "job-import" {
				t.Fatalf("import scope = %+v", imported)
			}
			if len(imported.Targets) != 1 ||
				imported.Targets[0].Address != "10.10.0.1" ||
				imported.Targets[0].Transport != device.TransportSNMPv2c ||
				imported.Targets[0].Credential != "core-ro" {
				t.Fatalf("imported targets = %+v", imported.Targets)
			}
			approved := 0
			for _, e := range imported.AuditEvents {
				if e.Action != device.AuditDiscoveryDeviceApproved {
					continue
				}
				approved++
				if e.TenantID != "tenant-a" || e.Subject != acceptedID || e.Actor != "lead@example.com" {
					t.Fatalf("approval audit event = %+v", e)
				}
			}
			if approved != 1 {
				t.Fatalf("expected exactly one %s audit event, got %d in %+v",
					device.AuditDiscoveryDeviceApproved, approved, imported.AuditEvents)
			}
		})
	}
}
