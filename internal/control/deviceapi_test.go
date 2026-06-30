// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/topology"
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
