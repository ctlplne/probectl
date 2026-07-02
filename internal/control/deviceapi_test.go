// SPDX-License-Identifier: LicenseRef-probectl-TBD

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

	devicepkg "github.com/imfeelingtheagi/probectl/internal/device"
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
