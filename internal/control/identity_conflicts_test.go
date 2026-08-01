// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
)

func TestBuildIdentityConflictViewsFreshnessAndConfidence(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	items := buildIdentityConflictViews([]topology.IdentityConflict{
		{
			ID: "active", Kind: topology.IdentityDeviceName, Subject: "10.0.0.1",
			Claims: []topology.IdentityClaim{
				{Value: "edge-a", Source: "snmp", LastSeen: now.Add(-time.Minute)},
				{Value: "edge-b", Source: "gnmi", LastSeen: now.Add(-2 * time.Minute)},
			},
		},
		{
			ID: "stale", Kind: topology.IdentityInterfaceName, Subject: "10.0.0.1@7",
			Claims: []topology.IdentityClaim{
				{Value: "Gi0/7", Source: "snmp", LastSeen: now.Add(-2 * time.Hour)},
				{Value: "Ethernet7", Source: "gnmi", LastSeen: now.Add(-3 * time.Hour)},
			},
		},
		{
			ID: "future", Kind: topology.IdentityManagementAddress, Subject: "edge-a",
			Claims: []topology.IdentityClaim{
				{Value: "10.0.0.1", Source: "snmp", LastSeen: now},
				{Value: "10.0.0.2", Source: "gnmi", LastSeen: now.Add(10 * time.Minute)},
			},
		},
	}, now)
	byID := map[string]identityConflictView{}
	for _, item := range items {
		byID[item.ID] = item
	}
	if got := byID["active"]; got.Status != "active" || got.Confidence != "high" {
		t.Fatalf("active = %+v", got)
	}
	if got := byID["stale"]; got.Status != "stale" || got.Confidence != "low" {
		t.Fatalf("stale = %+v", got)
	}
	if got := byID["future"]; got.Status != "unknown" || got.Claims[1].Freshness != "future" {
		t.Fatalf("future = %+v", got)
	}
}

func TestIdentityConflictAPIIngestsCompetingSourcesAndIsTenantScoped(t *testing.T) {
	store := topology.NewIndexedStore()
	consumer := NewTopologyConsumer(nil, store, t6Log())
	now := time.Now().UTC().Add(-time.Minute)
	defaultTenant := tenancy.DefaultTenantID.String()
	batch := &devicev1.DeviceMetricBatch{Metrics: []*devicev1.DeviceMetric{
		{
			TenantId: defaultTenant, AgentId: "agent-snmp", Source: "snmp",
			DeviceAddress: "10.0.0.1", DeviceName: "edge-primary",
			IfIndex: 7, IfName: "Gi0/7", TimeUnixNano: now.UnixNano(),
			InterfaceAddresses: []string{"192.0.2.7"},
		},
		{
			TenantId: defaultTenant, AgentId: "agent-gnmi", Source: "gnmi",
			DeviceAddress: "10.0.0.1", DeviceName: "edge-secondary",
			IfIndex: 7, IfName: "Ethernet7", TimeUnixNano: now.Add(time.Second).UnixNano(),
			InterfaceAddresses: []string{"192.0.2.8"},
		},
		{
			TenantId: defaultTenant, AgentId: "agent-snmp-2", Source: "snmp",
			DeviceAddress: "10.0.0.2", DeviceName: "edge-other",
			IfIndex: 8, IfName: "Gi0/8", TimeUnixNano: now.Add(2 * time.Second).UnixNano(),
			InterfaceAddresses: []string{"192.0.2.7"},
		},
		{
			TenantId: otherTenant, AgentId: "agent-secret", Source: "gnmi",
			DeviceAddress: "10.99.0.1", DeviceName: "tenant-b-secret-one",
			TimeUnixNano: now.UnixNano(),
		},
		{
			TenantId: otherTenant, AgentId: "agent-secret-2", Source: "snmp",
			DeviceAddress: "10.99.0.1", DeviceName: "tenant-b-secret-two",
			TimeUnixNano: now.Add(time.Second).UnixNano(),
		},
	}}
	if err := consumer.handleDevice(context.Background(), bus.Message{
		Value: mustTopologyProto(t, batch),
	}); err != nil {
		t.Fatal(err)
	}

	srv := testServer(fakePinger{}).WithTopology(store)
	rec := do(srv, http.MethodGet, "/v1/device/identity-conflicts?kind=device_name&source=gnmi&status=active&limit=20")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Items           []identityConflictView `json:"items"`
		TopologyRunning bool                   `json:"topology_running"`
		Truncated       bool                   `json:"truncated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.TopologyRunning || response.Truncated || len(response.Items) != 1 {
		t.Fatalf("response = %+v", response)
	}
	got := response.Items[0]
	if got.Subject != "10.0.0.1" || got.Status != "active" || got.Confidence != "high" ||
		got.ReviewProposal.Mode != "read_only" || got.ReviewProposal.MergeSupported {
		t.Fatalf("conflict = %+v", got)
	}
	if len(got.Claims) != 2 || len(got.AffectedCorrelations) == 0 {
		t.Fatalf("conflict lacks bounded provenance/correlations: %+v", got)
	}
	bound, err := store.ForTenant(defaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	if conflict := findConflictKind(bound.IdentityConflicts().Items, topology.IdentityInterfaceAddress); conflict == nil {
		t.Fatal("interface addresses carried through the real bus payload did not produce a conflict")
	}
	body := rec.Body.String()
	for _, forbidden := range []string{"tenant-b-secret", "10.99.0.1", "agent-secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("CROSS-TENANT LEAK %q: %s", forbidden, body)
		}
	}
}

func findConflictKind(
	items []topology.IdentityConflict,
	kind topology.IdentityConflictKind,
) *topology.IdentityConflict {
	for i := range items {
		if items[i].Kind == kind {
			return &items[i]
		}
	}
	return nil
}

func TestIdentityConflictAPIHonestUnavailableAndValidationStates(t *testing.T) {
	srv := testServer(fakePinger{})
	rec := do(srv, http.MethodGet, "/v1/device/identity-conflicts")
	if rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"topology_running":false`) ||
		!strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Fatalf("unwired response = %d %s", rec.Code, rec.Body.String())
	}
	for _, path := range []string{
		"/v1/device/identity-conflicts?kind=wrong",
		"/v1/device/identity-conflicts?status=resolved",
		"/v1/device/identity-conflicts?limit=nope",
	} {
		if rec = do(srv, http.MethodGet, path); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d body=%s", path, rec.Code, rec.Body.String())
		}
	}
}
