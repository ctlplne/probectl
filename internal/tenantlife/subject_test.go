// SPDX-License-Identifier: LicenseRef-probectl-TBD

package tenantlife

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/endpoint"
	"github.com/imfeelingtheagi/probectl/internal/store/ebpfstore"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/otelstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

func TestSubjectLifecycleMemoryTelemetryExportErase(t *testing.T) {
	ctx := context.Background()
	subject := "alice@example.com"
	flows := flowstore.NewMemory()
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	if err := flows.Insert(ctx, []flowstore.Row{
		{TenantID: "tenant-a", AgentID: subject, Exporter: "router-a", TS: now, SrcAddr: "198.51.100.1", DstAddr: "203.0.113.1", Bytes: 10, Packets: 1},
		{TenantID: "tenant-a", AgentID: "bob@example.com", Exporter: "router-a", TS: now, SrcAddr: "198.51.100.2", DstAddr: "203.0.113.2", Bytes: 20, Packets: 2},
		{TenantID: "tenant-b", AgentID: subject, Exporter: "router-b", TS: now, SrcAddr: "198.51.100.1", DstAddr: "203.0.113.9", Bytes: 30, Packets: 3},
	}); err != nil {
		t.Fatal(err)
	}
	otel := otelstore.NewMemory()
	if err := otel.WriteSpans(ctx, []otelstore.Span{
		{TenantID: "tenant-a", TraceID: "ta", SpanID: "sa", Name: "checkout " + subject, Service: "checkout", Start: now},
		{TenantID: "tenant-b", TraceID: "tb", SpanID: "sb", Name: "checkout " + subject, Service: "checkout", Start: now},
	}); err != nil {
		t.Fatal(err)
	}
	if err := otel.WriteLogs(ctx, []otelstore.LogRecord{
		{TenantID: "tenant-a", TS: now, Service: "checkout", Body: "login " + subject},
		{TenantID: "tenant-b", TS: now, Service: "checkout", Body: "login " + subject},
	}); err != nil {
		t.Fatal(err)
	}
	topo := topology.NewMemoryStore()
	taTopo, err := topo.ForTenant("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	taTopo.ObservePath(topology.PathInput{
		AgentID: "agent-a", Target: subject, TargetIP: "203.0.113.44",
		Hops: []string{"192.0.2.44"},
	}, now)
	taTopo.ObserveDevice(topology.DeviceInput{
		Address:      "198.51.100.44",
		Name:         subject,
		InterfaceIPs: []string{"192.0.2.44"},
	}, now)
	edges := ebpfstore.NewMemory()
	if err := edges.Insert(ctx, []ebpfstore.Edge{{
		TenantID: "tenant-a", AgentID: "node-a", WindowStart: now,
		SrcWorkload: subject, DstWorkload: "checkout", DstPort: 443,
		Bytes: 100, Packets: 10, Connections: 1,
	}}); err != nil {
		t.Fatal(err)
	}
	endpoints := endpoint.NewSnapshotStore(0)
	endpoints.Record("tenant-a", "laptop-a", endpoint.ResultView{
		Type: endpoint.TypeWiFi, Target: subject, Success: true, ObservedAt: now,
		Attributes: map[string]string{"wifi.ssid": subject},
	})
	mem := tsdb.NewMemory()
	if err := mem.Write(ctx, []tsdb.Series{
		{Metric: "rum.lcp_ms", Labels: map[string]string{"tenant_id": "tenant-a", "rum.host": subject, "url.path": "/users/" + subject}, Value: 1800},
		{Metric: "probectl_device_if_oper_status", Labels: map[string]string{"tenant_id": "tenant-a", "device_name": subject, "if_name": subject}, Value: 1},
	}); err != nil {
		t.Fatal(err)
	}

	e := New(nil, flows, nil, mem, nil, "backups expire by policy", nil).
		WithOtel(otel).
		WithTopology(topo).
		WithEBPF(edges).
		WithEndpointRetention(endpoints)
	var bundle bytes.Buffer
	man, err := e.ExportSubject(ctx, "tenant-a", subject, &bundle, false)
	if err != nil {
		t.Fatalf("subject export: %v", err)
	}
	if man.SubjectHash == "" {
		t.Fatal("subject export must store only a tenant-scoped subject hash in the manifest")
	}
	files := readTarGz(t, bundle.Bytes())
	for _, name := range []string{"flows.jsonl", "otel_spans.jsonl", "otel_logs.jsonl", "manifest.json"} {
		if files[name] == "" {
			t.Fatalf("missing %s in subject bundle; files=%v", name, files)
		}
	}
	if strings.Contains(files["flows.jsonl"], "router-b") || strings.Contains(files["otel_spans.jsonl"], `"tenant_id":"tenant-b"`) {
		t.Fatalf("subject export leaked another tenant:\nflows=%s\nspans=%s", files["flows.jsonl"], files["otel_spans.jsonl"])
	}
	exportPlanes := subjectPlanesByName(man.Planes)
	if exportPlanes["flows"].Rows != 1 || exportPlanes["otel_spans"].Rows != 1 || exportPlanes["otel_logs"].Rows != 1 {
		t.Fatalf("export counts missing subject-addressable planes: %+v", exportPlanes)
	}
	for _, plane := range []string{"topology", "ebpf", "rum", "device", "endpoint"} {
		if exportPlanes[plane].Status != SubjectStatusNotAddressable {
			t.Fatalf("export plane %s status = %+v, want not-addressable", plane, exportPlanes[plane])
		}
	}

	report, err := e.EraseSubject(ctx, "tenant-a", subject, "privacy-admin", "dsar")
	if err != nil {
		t.Fatalf("subject erase: %v", err)
	}
	if !report.Complete || report.ReportSHA256 == "" {
		t.Fatalf("subject erasure report incomplete/unhashed: %+v", report)
	}
	erasePlanes := subjectPlanesByName(report.Planes)
	if erasePlanes["flows"].Deleted != 1 || erasePlanes["flows"].Remaining != 0 {
		t.Fatalf("flow erasure receipt = %+v", erasePlanes["flows"])
	}
	if erasePlanes["otel"].Deleted != 2 || erasePlanes["otel"].Remaining != 0 {
		t.Fatalf("otel erasure receipt = %+v", erasePlanes["otel"])
	}
	for _, plane := range []string{"topology", "ebpf", "rum", "device", "endpoint"} {
		if erasePlanes[plane].Status != SubjectStatusNotAddressable {
			t.Fatalf("erase plane %s status = %+v, want not-addressable", plane, erasePlanes[plane])
		}
	}
	var afterA bytes.Buffer
	if _, err := flows.ExportTenant(ctx, "tenant-a", &afterA); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(afterA.String(), subject) {
		t.Fatalf("tenant-a flow subject survived erase: %s", afterA.String())
	}
	var afterB bytes.Buffer
	if _, err := flows.ExportTenant(ctx, "tenant-b", &afterB); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(afterB.String(), subject) {
		t.Fatalf("tenant-b matching subject must be untouched: %s", afterB.String())
	}
	spansA, _ := otel.QuerySpans(ctx, "tenant-a", otelstore.SpanQuery{})
	logsA, _ := otel.QueryLogs(ctx, "tenant-a", otelstore.LogQuery{})
	if len(spansA) != 0 || len(logsA) != 0 {
		t.Fatalf("tenant-a otel subject survived erase: spans=%v logs=%v", spansA, logsA)
	}
	spansB, _ := otel.QuerySpans(ctx, "tenant-b", otelstore.SpanQuery{})
	logsB, _ := otel.QueryLogs(ctx, "tenant-b", otelstore.LogQuery{})
	if len(spansB) != 1 || len(logsB) != 1 {
		t.Fatalf("tenant-b otel rows must be untouched: spans=%v logs=%v", spansB, logsB)
	}
}

func subjectPlanesByName(planes []SubjectPlaneResult) map[string]SubjectPlaneResult {
	out := map[string]SubjectPlaneResult{}
	for _, p := range planes {
		out[p.Plane] = p
	}
	return out
}

func readTarGz(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = string(b)
	}
}
