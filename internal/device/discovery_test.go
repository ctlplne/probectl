// SPDX-License-Identifier: LicenseRef-probectl-TBD

package device

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryFixtureClassifiesAndRequiresReview(t *testing.T) {
	now := fixedClock(time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC))
	job := DiscoveryJob{
		ID:        "job-1",
		TenantID:  "tenant-a",
		CreatedBy: "netops@example.com",
		Ranges:    []string{"10.0.0.0/30"},
		Credentials: []DiscoveryCredential{{
			TenantID: "tenant-a", Name: "core-ro", Transport: TransportSNMPv2c,
		}},
		ClassifierRules: []ClassifierRule{
			{Role: "core-router", SysNameContains: []string{"core"}, SysDescrContains: []string{"router"}, Confidence: 0.93},
			{Role: "access-switch", SysNameContains: []string{"access"}, SysDescrContains: []string{"switch"}, Confidence: 0.91},
		},
		MaxHosts: 2,
	}
	fixture := FixtureDiscoveryProber{
		"10.0.0.1": {
			Device:   "10.0.0.1",
			SysName:  "core-r1",
			SysDescr: "router os",
			Interfaces: map[uint32]Interface{
				1: {Index: 1, Name: "ge-0/0/0", Descr: "wan uplink", SpeedMbps: 10000, OperUp: true, Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
			},
		},
		"10.0.0.2": {
			Device:   "10.0.0.2",
			SysName:  "access-sw1",
			SysDescr: "switch os",
			Interfaces: map[uint32]Interface{
				7: {Index: 7, Name: "Gi0/7", Descr: "user port", SpeedMbps: 1000, OperUp: true},
			},
		},
	}

	result, err := RunDiscovery(context.Background(), job, mapCreds{"core-ro": {Community: "public"}}, fixture, now)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if result.Status != DiscoveryStatusReviewRequired || len(result.Devices) != 2 {
		t.Fatalf("result = %+v", result)
	}
	assertDevice := func(idx int, address, role string) DiscoveredDevice {
		t.Helper()
		d := result.Devices[idx]
		if d.TenantID != "tenant-a" || d.Address != address || d.Role != role ||
			d.ActivationState != ActivationPendingReview || d.Credential != "core-ro" ||
			d.Transport != TransportSNMPv2c || len(d.Interfaces) == 0 {
			t.Fatalf("device[%d] = %+v", idx, d)
		}
		return d
	}
	core := assertDevice(0, "10.0.0.1", "core-router")
	access := assertDevice(1, "10.0.0.2", "access-switch")
	if core.Interfaces[0].Addrs[0] != "10.0.0.1" || access.Interfaces[0].Name != "Gi0/7" {
		t.Fatalf("interfaces not preserved: core=%+v access=%+v", core.Interfaces, access.Interfaces)
	}
	if !hasAudit(result.AuditEvents, AuditDiscoveryJobStarted) ||
		!hasAudit(result.AuditEvents, AuditDiscoveryDeviceFound) ||
		!hasAudit(result.AuditEvents, AuditDiscoveryReviewRequired) {
		t.Fatalf("missing audit receipt events: %+v", result.AuditEvents)
	}

	targets, events, err := BuildDiscoveryImport(result, DiscoveryReview{
		TenantID:        "tenant-a",
		JobID:           "job-1",
		ReviewedBy:      "lead@example.com",
		AcceptDeviceIDs: []string{core.ID},
	}, now)
	if err != nil {
		t.Fatalf("review: %v", err)
	}
	if len(targets) != 1 || targets[0].Address != "10.0.0.1" || targets[0].Credential != "core-ro" {
		t.Fatalf("targets = %+v", targets)
	}
	if len(events) != 1 || events[0].Action != AuditDiscoveryDeviceApproved || events[0].TenantID != "tenant-a" {
		t.Fatalf("events = %+v", events)
	}
}

func TestDiscoveryStoreTenantIsolation(t *testing.T) {
	store := NewMemoryDiscoveryStore()
	a := DiscoveryResult{TenantID: "tenant-a", JobID: "job-a", Status: DiscoveryStatusReviewRequired,
		Devices: []DiscoveredDevice{{ID: "a", TenantID: "tenant-a", Address: "10.0.0.1"}}}
	b := DiscoveryResult{TenantID: "tenant-b", JobID: "job-b", Status: DiscoveryStatusReviewRequired,
		Devices: []DiscoveredDevice{{ID: "b", TenantID: "tenant-b", Address: "10.1.0.1"}}}
	if err := store.SaveDiscoveryResult(a); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDiscoveryResult(b); err != nil {
		t.Fatal(err)
	}
	rows := store.ListDiscoveryResults("tenant-a")
	if len(rows) != 1 || rows[0].JobID != "job-a" || rows[0].Devices[0].Address != "10.0.0.1" {
		t.Fatalf("tenant-a rows = %+v", rows)
	}
	if _, ok := store.GetDiscoveryResult("tenant-a", "job-b"); ok {
		t.Fatal("tenant-a could read tenant-b discovery result")
	}
	if _, ok := store.GetDiscoveryResult("tenant-b", "job-b"); !ok {
		t.Fatal("tenant-b could not read its own result")
	}
}

func TestDiscoveryValidationSafeRangesAndCredentialScope(t *testing.T) {
	base := DiscoveryJob{
		ID:       "job-safe",
		TenantID: "tenant-a",
		Ranges:   []string{"10.0.0.1"},
		Credentials: []DiscoveryCredential{{
			TenantID: "tenant-a", Name: "ro", Transport: TransportSNMPv2c,
		}},
		MaxHosts: 1,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("base validate: %v", err)
	}
	public := base
	public.Ranges = []string{"8.8.8.0/24"}
	if err := public.Validate(); !errors.Is(err, ErrUnsafeDiscoveryRange) {
		t.Fatalf("public range error = %v", err)
	}
	tooWide := base
	tooWide.Ranges = []string{"10.0.0.0/24"}
	if err := tooWide.Validate(); !errors.Is(err, ErrUnsafeDiscoveryRange) {
		t.Fatalf("wide range error = %v", err)
	}
	wrongTenant := base
	wrongTenant.Credentials = []DiscoveryCredential{{TenantID: "tenant-b", Name: "ro", Transport: TransportSNMPv2c}}
	if err := wrongTenant.Validate(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("tenant mismatch error = %v", err)
	}
}

func TestLoadDiscoveryFixture(t *testing.T) {
	prober, err := LoadDiscoveryFixture(strings.NewReader(`{
	  "devices": [{
	    "address": "10.0.0.5",
	    "sys_name": "edge-r1",
	    "sys_descr": "router",
	    "interfaces": [{"index": 1, "name": "wan0", "addrs": ["10.0.0.5"], "oper_up": true}]
	  }]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := prober.Probe(context.Background(), Target{Address: "10.0.0.5", Credential: "ro"}, Credential{Community: "public"})
	if err != nil {
		t.Fatal(err)
	}
	if inv.SysName != "edge-r1" || inv.Interfaces[1].Addrs[0].String() != "10.0.0.5" {
		t.Fatalf("fixture inventory = %+v", inv)
	}
}

func hasAudit(events []DiscoveryAuditEvent, action string) bool {
	for _, e := range events {
		if e.Action == action {
			return true
		}
	}
	return false
}

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}
