// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

	"github.com/ctlplne/probectl/internal/endpoint"
	"github.com/ctlplne/probectl/internal/store/ebpfstore"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/topology"
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
	for _, name := range []string{
		"flows.jsonl",
		"otel_spans.jsonl",
		"otel_logs.jsonl",
		"tsdb_metrics.jsonl",
		"topology_subject.jsonl",
		"ebpf_edges.jsonl",
		"endpoint_subject.jsonl",
		"manifest.json",
	} {
		if files[name] == "" {
			t.Fatalf("missing %s in subject bundle; files=%v", name, files)
		}
	}
	if strings.Contains(files["flows.jsonl"], "router-b") ||
		strings.Contains(files["otel_spans.jsonl"], `"tenant_id":"tenant-b"`) ||
		strings.Contains(files["tsdb_metrics.jsonl"], `"tenant_id":"tenant-b"`) {
		t.Fatalf("subject export leaked another tenant:\nflows=%s\nspans=%s\ntsdb=%s",
			files["flows.jsonl"], files["otel_spans.jsonl"], files["tsdb_metrics.jsonl"])
	}
	exportPlanes := subjectPlanesByName(man.Planes)
	if exportPlanes["flows"].Rows != 1 || exportPlanes["otel_spans"].Rows != 1 || exportPlanes["otel_logs"].Rows != 1 {
		t.Fatalf("export counts missing subject-addressable planes: %+v", exportPlanes)
	}
	for _, plane := range []string{"tsdb_metrics", "topology", "ebpf", "device", "endpoint"} {
		if exportPlanes[plane].Status != SubjectStatusExported || exportPlanes[plane].Rows == 0 {
			t.Fatalf("export plane %s status = %+v, want exported rows", plane, exportPlanes[plane])
		}
	}
	if exportPlanes["rum"].Status != SubjectStatusCoveredByPlane || exportPlanes["rum"].Rows == 0 {
		t.Fatalf("rum export receipt = %+v, want covered by tsdb_metrics", exportPlanes["rum"])
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
	for _, plane := range []string{"tsdb_metrics", "topology", "ebpf", "device", "endpoint"} {
		if erasePlanes[plane].Status != SubjectStatusDeleted || erasePlanes[plane].Remaining != 0 {
			t.Fatalf("erase plane %s receipt = %+v, want deleted/remaining=0", plane, erasePlanes[plane])
		}
	}
	if erasePlanes["rum"].Status != SubjectStatusCoveredByPlane || erasePlanes["rum"].Remaining != 0 {
		t.Fatalf("rum erase receipt = %+v, want covered by tsdb_metrics", erasePlanes["rum"])
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
	for _, s := range mem.Snapshot() {
		if s.Labels["tenant_id"] != "tenant-a" {
			continue
		}
		for _, v := range s.Labels {
			if strings.Contains(v, subject) {
				t.Fatalf("tenant-a tsdb subject survived erase: %+v", s)
			}
		}
	}
	snap := topo.Latest("tenant-a")
	for _, n := range snap.Nodes {
		if strings.Contains(n.ID+n.Label, subject) {
			t.Fatalf("tenant-a topology node subject survived erase: %+v", n)
		}
		for _, v := range n.Attributes {
			if strings.Contains(v, subject) {
				t.Fatalf("tenant-a topology node attr subject survived erase: %+v", n)
			}
		}
	}
	for _, e := range snap.Edges {
		if strings.Contains(e.ID+e.From+e.To+e.Label, subject) {
			t.Fatalf("tenant-a topology edge subject survived erase: %+v", e)
		}
	}
	top, err := edges.TopEdges(ctx, "tenant-a", ebpfstore.EdgeQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range top {
		if strings.Contains(e.SrcWorkload+e.DstWorkload+e.AgentID, subject) {
			t.Fatalf("tenant-a ebpf subject survived erase: %+v", e)
		}
	}
	if got := endpoints.List("tenant-a"); len(got) != 0 {
		t.Fatalf("tenant-a endpoint subject survived erase: %+v", got)
	}
}

func TestSubjectErasureNotCapablePlanesIncomplete(t *testing.T) {
	engine := New(nil, nil, nil, subjectEraseIncapableTSDB{}, nil, "backups expire by policy", nil).
		WithTopology(subjectEraseIncapableTopology{}).
		WithEBPF(subjectEraseIncapableEBPF{}).
		WithEndpointRetention(subjectEraseIncapableEndpoint{})

	report, err := engine.EraseSubject(
		context.Background(),
		"tenant-a",
		"alice@example.com",
		"privacy-admin",
		"dsar",
	)
	if err != nil {
		t.Fatalf("subject erase: %v", err)
	}
	if report.Complete {
		t.Fatalf("deployed not-capable planes produced complete receipt: %+v", report)
	}
	if report.ReportSHA256 == "" {
		t.Fatal("incomplete subject-erasure receipt must still be hashed")
	}

	planes := subjectPlanesByName(report.Planes)
	for _, plane := range []string{"tsdb_metrics", "rum", "topology", "device", "ebpf", "endpoint"} {
		if got := planes[plane]; got.Status != SubjectStatusNotCapable {
			t.Errorf("%s receipt = %+v, want status %q", plane, got, SubjectStatusNotCapable)
		}
	}
}

type subjectEraseIncapableTSDB struct{}

func (subjectEraseIncapableTSDB) Write(context.Context, []tsdb.Series) error { return nil }
func (subjectEraseIncapableTSDB) Close() error                               { return nil }

type subjectEraseIncapableTopology struct{}

func (subjectEraseIncapableTopology) DeleteTenant(string) int { return 0 }

type subjectEraseIncapableEBPF struct{}

func (subjectEraseIncapableEBPF) DeleteTenant(context.Context, string) (int64, error) {
	return 0, nil
}

type subjectEraseIncapableEndpoint struct{}

func (subjectEraseIncapableEndpoint) PruneTenantBefore(string, time.Time) int { return 0 }

func TestLiteralILikeContainsPatternEscapesMetacharacters(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "plain", value: "alice@example.test", want: "%alice@example.test%"},
		{name: "percent and underscore", value: "account%_owner", want: "%account!%!_owner%"},
		{name: "escape character", value: "bang!%_", want: "%bang!!!%!_%"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := literalILikeContainsPattern(tt.value); got != tt.want {
				t.Fatalf("literalILikeContainsPattern(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestSubjectPostgresClassificationFailsClosedOnUnknownTenantTable(t *testing.T) {
	_, err := classifySubjectPostgresTables([]string{"users", "future_subject_records"})
	if err == nil {
		t.Fatal("unknown tenant-owned table was silently treated as subject-erasure complete")
	}
	if !strings.Contains(err.Error(), "future_subject_records") ||
		!strings.Contains(err.Error(), "unclassified tenant-owned tables") {
		t.Fatalf("classification error = %q", err)
	}

	classified, err := classifySubjectPostgresTables([]string{
		"users",
		"audit_events",
		"ai_feedback",
		"incident_correlation_overrides",
		"roles",
		"ir_attribution_records",
	})
	if err != nil {
		t.Fatalf("known subject table inventory: %v", err)
	}
	byName := make(map[string]subjectTableDisposition, len(classified))
	for _, table := range classified {
		byName[table.name] = table.policy.disposition
	}
	if byName["audit_events"] != subjectTableProjectMatches {
		t.Fatalf("audit_events disposition = %d, want append-only projection", byName["audit_events"])
	}
	for _, table := range []string{"users", "ai_feedback", "incident_correlation_overrides"} {
		if byName[table] != subjectTableDeleteMatches {
			t.Fatalf("%s disposition = %d, want count-verified deletion", table, byName[table])
		}
	}
	if byName["roles"] != subjectTableNoSubject {
		t.Fatalf("roles disposition = %d, want explicit no-subject classification", byName["roles"])
	}
	if byName["ir_attribution_records"] != subjectTableRetainEncryptedEvidence {
		t.Fatalf(
			"ir_attribution_records disposition = %d, want retained encrypted evidence",
			byName["ir_attribution_records"],
		)
	}
}

func TestSafeContainsIdentifierRejectsGenericFreeform(t *testing.T) {
	for _, value := range []string{"read", "active", "admin", "Read-only administrator"} {
		if isSafeContainsIdentifier(value) {
			t.Errorf("%q was accepted for substring subject matching", value)
		}
	}
	for _, value := range []string{
		"alice@example.test",
		"00000000-0000-0000-0000-000000000123",
		"192.0.2.10",
		"2001:db8::10",
		"spiffe://probectl/tenant/t/agent/a",
	} {
		if !isSafeContainsIdentifier(value) {
			t.Errorf("%q was rejected as an unambiguous structured identifier", value)
		}
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
