// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store/ebpfstore"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/topology"
)

// TestExportCarriesEveryPlaneErasureClears: the runbook's order is export,
// then erase. Erasure clears the OTLP, eBPF, path and topology stores, but the
// bundle carried none of them, so a tenant who exported first still lost its
// traces, logs, service map and path history. Each plane must be in the
// bundle, counted in the manifest, and hold only the exporting tenant's rows.
func TestExportCarriesEveryPlaneErasureClears(t *testing.T) {
	ctx := context.Background()
	otel := otelstore.NewMemory()
	edges := ebpfstore.NewMemory()
	paths := pathstore.NewMemory()
	topo := topology.WithTenantWriteFence(topology.NewIndexedStore(), openWriterFence{})
	for _, tenant := range []string{"tnA", "tnB"} {
		mark := "svc-" + tenant
		if err := otel.WriteSpans(ctx, []otelstore.Span{{TenantID: tenant, TraceID: "t-" + tenant, SpanID: "s-" + tenant, Name: "checkout", Service: mark, Start: t0}}); err != nil {
			t.Fatal(err)
		}
		if err := otel.WriteLogs(ctx, []otelstore.LogRecord{{TenantID: tenant, TS: t0, Service: mark, Body: "paid"}}); err != nil {
			t.Fatal(err)
		}
		if err := edges.Insert(ctx, []ebpfstore.Edge{{TenantID: tenant, AgentID: "node-1", WindowStart: t0, SrcWorkload: mark, DstWorkload: "db", DstPort: 5432, Bytes: 10, Packets: 1, Connections: 1}}); err != nil {
			t.Fatal(err)
		}
		if err := paths.Save(ctx, tenant, &path.Path{Target: mark, TargetIP: "192.0.2.10", Mode: "icmp",
			Hops:  []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: "192.0.2.1", Sent: 3, Received: 3}}}, {TTL: 2, Nodes: []path.HopNode{{IP: "192.0.2.10", Sent: 3, Received: 3}}}},
			Links: []path.Link{{TTL: 1, From: "192.0.2.1", To: "192.0.2.10"}},
		}); err != nil {
			t.Fatal(err)
		}
		graph, err := topo.ForTenant(tenant)
		if err != nil {
			t.Fatal(err)
		}
		graph.ObserveServiceEdge(topology.ServiceEdgeInput{Source: mark, Destination: "db", DestPort: 5432}, t0)
	}
	td, ok := topo.(TopologyDeleter)
	if !ok {
		t.Fatal("the fenced topology store does not offer tenant deletion")
	}
	e := New(nil, nil, nil, nil, nil, "", testLog()).
		WithClock(func() time.Time { return t0 }).
		WithOtel(otel).WithEBPF(edges).WithPaths(paths).WithTopology(td)

	var buf bytes.Buffer
	man, err := e.Export(ctx, "tnA", &buf)
	if err != nil {
		t.Fatal(err)
	}
	files := readTarGz(t, buf.Bytes())
	for file, count := range map[string]int64{
		"otel_spans.jsonl": man.OtelSpans, "otel_logs.jsonl": man.OtelLogs, "ebpf_edges.jsonl": man.EBPFEdges,
		"path_hops.jsonl": man.PathHops, "path_links.jsonl": man.PathLinks, "topology.jsonl": man.Topology,
	} {
		lines := int64(strings.Count(files[file], "\n"))
		if lines == 0 || lines != count {
			t.Errorf("%s holds %d lines, manifest counts %d:\n%s", file, lines, count, files[file])
		}
		if !strings.Contains(files[file], "svc-tnA") {
			t.Errorf("%s does not carry tenant A's rows:\n%s", file, files[file])
		}
		if strings.Contains(files[file], "tnB") {
			t.Errorf("%s leaked tenant B's rows:\n%s", file, files[file])
		}
	}
	want := map[string]int64{"otel_spans": 1, "otel_logs": 1, "ebpf_edges": 1, "path_hops": 2, "path_links": 1, "topology": 3}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(files["manifest.json"]), &parsed); err != nil {
		t.Fatal(err)
	}
	for key, n := range want {
		if got, _ := parsed[key].(float64); int64(got) != n {
			t.Errorf("manifest %s = %v, want %d", key, parsed[key], n)
		}
	}
	for _, note := range man.Notes {
		if strings.Contains(note, "cannot export") {
			t.Errorf("every store here can export, but the manifest says: %s", note)
		}
	}
}

// TestExportNamesAStoreThatCannotExport: a deployed store without an export
// method is named in the manifest notes, never silently missing.
func TestExportNamesAStoreThatCannotExport(t *testing.T) {
	e := New(nil, nil, nil, nil, nil, "", testLog()).WithPaths(deleteOnlyPaths{})
	var buf bytes.Buffer
	man, err := e.Export(context.Background(), "tnA", &buf)
	if err != nil {
		t.Fatal(err)
	}
	named := false
	for _, note := range man.Notes {
		named = named || (strings.Contains(note, "cannot export") && strings.Contains(note, "paths"))
	}
	if !named {
		t.Fatalf("the manifest notes do not name the path store that cannot export: %q", man.Notes)
	}
}

type deleteOnlyPaths struct{}

func (deleteOnlyPaths) DeleteTenant(context.Context, string) (int, int, error) { return 0, 0, nil }
