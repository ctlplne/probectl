// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	devicepkg "github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
)

func TestDeviceInventoryAPIReadsTenantTopology(t *testing.T) {
	topo := topology.NewIndexedStore()
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	def := tenancy.DefaultTenantID.String()
	topo.ObserveDevice(def, topology.DeviceInput{Address: "10.0.0.1", Name: "edge-r1", InterfaceIPs: []string{"192.0.2.1"}}, now)
	topo.ObserveDevice(otherTenant, topology.DeviceInput{Address: "10.0.0.99", Name: "secret-sw"}, now)
	srv := testServer(fakePinger{}).WithTopology(topo)

	rec := do(srv, http.MethodGet, "/v1/devices")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		TopologyRunning bool                  `json:"topology_running"`
		Items           []deviceInventoryItem `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.TopologyRunning || len(resp.Items) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	if got := resp.Items[0]; got.Address != "10.0.0.1" || got.Name != "edge-r1" || got.Labels["probectl.device.address"] != "10.0.0.1" {
		t.Fatalf("device = %+v", got)
	}
	if strings.Contains(rec.Body.String(), "secret-sw") || strings.Contains(rec.Body.String(), "10.0.0.99") {
		t.Fatalf("CROSS-TENANT LEAK: %s", rec.Body.String())
	}
}

func TestDeviceMetricsAPILatestSummariesAreTenantScoped(t *testing.T) {
	mem := tsdb.NewMemory()
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	def := tenancy.DefaultTenantID.String()
	if err := mem.Write(context.Background(), []tsdb.Series{
		{Metric: "probectl_device_cpu_utilization", Labels: map[string]string{
			"tenant_id": def, "agent_id": "collector-1", "device": "10.0.0.1", "device_name": "edge-r1", "source": "snmp",
		}, Value: 40, TimeMillis: now.Add(-time.Minute).UnixMilli()},
		{Metric: "probectl_device_cpu_utilization", Labels: map[string]string{
			"tenant_id": def, "agent_id": "collector-1", "device": "10.0.0.1", "device_name": "edge-r1", "source": "snmp",
		}, Value: 42, TimeMillis: now.UnixMilli()},
		{Metric: "probectl_device_if_in_octets", Labels: map[string]string{
			"tenant_id": def, "agent_id": "collector-1", "device": "10.0.0.1", "if_index": "1", "if_name": "xe-0/0/0",
		}, Value: 1000, TimeMillis: now.UnixMilli()},
		{Metric: "probectl_device_cpu_utilization", Labels: map[string]string{
			"tenant_id": otherTenant, "agent_id": "collector-x", "device": "10.0.0.99", "device_name": "secret-sw",
		}, Value: 99, TimeMillis: now.UnixMilli()},
	}); err != nil {
		t.Fatal(err)
	}
	srv := testServer(fakePinger{}).WithTSDB(mem)

	rec := do(srv, http.MethodGet, "/v1/device/metrics?device=10.0.0.1&metric=probectl.device.cpu.utilization&limit=5")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		MetricsRunning bool                  `json:"metrics_running"`
		EffectiveLimit int                   `json:"effective_limit"`
		Items          []deviceMetricSummary `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.MetricsRunning || resp.EffectiveLimit != 5 || len(resp.Items) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	if got := resp.Items[0]; got.Device != "10.0.0.1" || got.DeviceName != "edge-r1" || got.Metric != "probectl_device_cpu_utilization" || got.Value != 42 {
		t.Fatalf("metric summary = %+v", got)
	}
	if strings.Contains(rec.Body.String(), "secret-sw") || strings.Contains(rec.Body.String(), "10.0.0.99") {
		t.Fatalf("CROSS-TENANT LEAK: %s", rec.Body.String())
	}
}

func TestDeviceNeighborAPITenantScopedWithFreshnessAndBounds(t *testing.T) {
	st := devicepkg.NewMemoryNeighborStore()
	now := time.Now().UTC().Add(-time.Minute)
	def := tenancy.DefaultTenantID.String()
	for tenant, pair := range map[string][2]string{
		def:         {"10.0.0.1", "leaf-a"},
		otherTenant: {"10.0.0.99", "secret-leaf-b"},
	} {
		deviceAddress, remote := pair[0], pair[1]
		if err := st.ReplaceSnapshot(context.Background(), tenant, devicepkg.NeighborSnapshot{
			TenantID: tenant, AgentID: "agent-1", DeviceAddress: deviceAddress,
			DeviceName: "core", ObservedAt: now,
			Neighbors: []devicepkg.NeighborEvidence{{
				LocalPortID: "xe-0/0/1", RemoteChassisID: remote,
				RemoteDeviceName: remote, RemotePortID: "Ethernet1",
				Protocol: devicepkg.NeighborProtocolLLDP, Confidence: 0.95,
				FreshUntil: now.Add(2 * time.Minute),
			}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	srv := testServer(fakePinger{}).WithDeviceNeighbors(st)
	rec := do(srv, http.MethodGet, "/v1/device/neighbors?protocol=lldp&limit=5")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp deviceNeighborResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.CollectionRunning || len(resp.Items) != 1 || resp.Items[0].RemoteDeviceName != "leaf-a" ||
		resp.Items[0].Freshness != "current" || resp.Retention.MaxPerDevice != devicepkg.MaxNeighborsPerDevice {
		t.Fatalf("response = %+v", resp)
	}
	if strings.Contains(rec.Body.String(), "secret-leaf-b") || strings.Contains(rec.Body.String(), "10.0.0.99") {
		t.Fatalf("CROSS-TENANT NEIGHBOR LEAK: %s", rec.Body.String())
	}
	if bad := do(srv, http.MethodGet, "/v1/device/neighbors?protocol=telnet"); bad.Code != http.StatusBadRequest {
		t.Fatalf("invalid protocol status = %d body=%s", bad.Code, bad.Body.String())
	}
}

func TestDeviceCollectionOutcomeAPITenantScopedVersionedAndRedacted(t *testing.T) {
	st := devicepkg.NewMemoryCollectionOutcomeStore()
	now := time.Now().UTC().Truncate(time.Second)
	def := tenancy.DefaultTenantID.String()
	for tenant, target := range map[string]string{
		def:         "router-a.internal",
		otherTenant: "secret-router-b.internal",
	} {
		at := now
		if err := st.UpsertCollectionOutcome(context.Background(), tenant, devicepkg.CollectionOutcome{
			TenantID: tenant, AgentID: "agent-1", ConfiguredTarget: target,
			Protocol: devicepkg.NeighborProtocolLLDP, LastAttemptAt: &at,
			State: devicepkg.CollectionStateFailed, Reason: devicepkg.CollectionReasonPollFailed,
			NextAction: devicepkg.CollectionActionVerifyLocalAccess,
		}); err != nil {
			t.Fatal(err)
		}
	}
	srv := testServer(fakePinger{}).WithDeviceCollectionOutcomes(st)
	rec := do(srv, http.MethodGet, "/v1/device/collection-outcomes?state=failed&limit=5")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp deviceCollectionOutcomeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ContractVersion != "probectl.device-collection-outcomes/v1" ||
		!resp.CollectionRunning || len(resp.Items) != 1 ||
		resp.Items[0].ConfiguredTarget != "router-a.internal" ||
		resp.Retention.MaxPerTenant != devicepkg.MaxCollectionOutcomesPerTenant {
		t.Fatalf("response = %+v", resp)
	}
	body := rec.Body.String()
	for _, forbidden := range []string{"secret-router-b", "community", "password", "raw_varbind"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatalf("collection outcome leaked forbidden data %q: %s", forbidden, body)
		}
	}
	if bad := do(srv, http.MethodGet, "/v1/device/collection-outcomes?state=unknown"); bad.Code != http.StatusBadRequest {
		t.Fatalf("invalid state status = %d body=%s", bad.Code, bad.Body.String())
	}
}

func TestDeviceCollectionOutcomeAPIReportsUnwiredHonestly(t *testing.T) {
	rec := do(testServer(fakePinger{}), http.MethodGet, "/v1/device/collection-outcomes")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"collection_running":false`) ||
		!strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Fatalf("unwired response status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDeviceSyslogAPITenantScoped(t *testing.T) {
	srv := testServer(fakePinger{})
	def := tenancy.DefaultTenantID.String()
	postJSONAsTenant(t, srv, http.MethodPost, "/v1/device/syslog", otherTenant,
		`{"device":"edge-b","raw":"<131>Jul  2 12:34:56 edge-b SECRET tenant-b"}`)
	postJSONAsTenant(t, srv, http.MethodPost, "/v1/device/syslog", def,
		`{"raw":"<134>Jul  2 12:35:00 edge-a Interface Gi0/1 down"}`)

	rec := do(srv, http.MethodGet, "/v1/device/syslog?limit=10")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items []devicepkg.SyslogEvent `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 || resp.Items[0].TenantID != def || resp.Items[0].Device != "edge-a" {
		t.Fatalf("syslog response = %+v", resp)
	}
	if strings.Contains(rec.Body.String(), "tenant-b") || strings.Contains(rec.Body.String(), "edge-b") {
		t.Fatalf("CROSS-TENANT SYSLOG LEAK: %s", rec.Body.String())
	}
}

func TestDeviceConfigArchiveAPIRedactsAndScopesTenant(t *testing.T) {
	srv := testServer(fakePinger{})
	def := tenancy.DefaultTenantID.String()
	postJSONAsTenant(t, srv, http.MethodPost, "/v1/device/configs", otherTenant,
		`{"device":"edge-b","content":"hostname edge-b\nsecret tenant-b-only\n"}`)
	first := postJSONAsTenant(t, srv, http.MethodPost, "/v1/device/configs", def,
		`{"device":"edge-a","source":"startup-config","content":"hostname edge-a\nenable secret raw-password\ninterface Gi0/1\n"}`)
	if !strings.Contains(first.Body.String(), "[redacted]") || strings.Contains(first.Body.String(), "raw-password") {
		t.Fatalf("archive response did not redact config secret: %s", first.Body.String())
	}
	postJSONAsTenant(t, srv, http.MethodPost, "/v1/device/configs", def,
		`{"device":"edge-a","source":"running-config","content":"hostname edge-a\ninterface Gi0/2\n"}`)

	rec := do(srv, http.MethodGet, "/v1/device/configs?device=edge-a&limit=10")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items []devicepkg.ConfigVersion `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 2 {
		t.Fatalf("config response = %+v", resp)
	}
	if !resp.Items[0].Drifted || resp.Items[0].Version != 2 || resp.Items[0].PreviousHash == "" {
		t.Fatalf("latest config did not report versioned drift: %+v", resp.Items[0])
	}
	if strings.Contains(rec.Body.String(), "tenant-b-only") || strings.Contains(rec.Body.String(), "edge-b") {
		t.Fatalf("CROSS-TENANT CONFIG LEAK: %s", rec.Body.String())
	}
}

func postJSONAsTenant(t *testing.T, srv *Server, method, path, tenant, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Probectl-Tenant", tenant)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code < 200 || rec.Code >= 300 {
		t.Fatalf("%s %s status = %d body=%s", method, path, rec.Code, rec.Body.String())
	}
	return rec
}
