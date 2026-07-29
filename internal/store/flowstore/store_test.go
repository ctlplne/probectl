// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flowstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

// seed inserts a deterministic mixed-tenant dataset:
//   - t-a: 10.0.0.1 -> 10.0.0.9 is the loud talker (3 flows, 30k scaled bytes
//     in AS 64500), 10.0.0.2 quieter, on exporter r1 iface 1
//   - t-b: one row that must NEVER surface in t-a queries.
func seed(t *testing.T, s Store) {
	t.Helper()
	rows := []Row{
		{TenantID: "t-a", Exporter: "r1", Protocol: "netflow5", TS: now.Add(-5 * time.Minute),
			SrcAddr: "10.0.0.1", DstAddr: "10.0.0.9", SrcASN: 64500, SrcASName: "ACME-NET",
			DstASN: 64510, DstASName: "DEST-NET", SrcCountry: "US", DstCountry: "DE",
			SrcPort: 12000, DstPort: 443, Transport: "tcp",
			InIf: 1, OutIf: 2, BytesScaled: 10_000, PacketsScaled: 10},
		{TenantID: "t-a", Exporter: "r1", Protocol: "netflow5", TS: now.Add(-4 * time.Minute),
			SrcAddr: "10.0.0.1", DstAddr: "10.0.0.9", SrcASN: 64500, SrcASName: "ACME-NET",
			DstASN: 64510, DstASName: "DEST-NET", SrcCountry: "US", DstCountry: "DE",
			SrcPort: 12001, DstPort: 443, Transport: "tcp",
			InIf: 1, OutIf: 2, BytesScaled: 12_000, PacketsScaled: 12},
		{TenantID: "t-a", Exporter: "r1", Protocol: "ipfix", TS: now.Add(-3 * time.Minute),
			SrcAddr: "10.0.0.1", DstAddr: "10.0.0.8", SrcASN: 64500, SrcASName: "ACME-NET",
			DstASN: 64511, DstASName: "BACKUP-NET", SrcCountry: "US", DstCountry: "GB",
			SrcPort: 12002, DstPort: 8443, Transport: "tcp",
			InIf: 1, OutIf: 2, BytesScaled: 8_000, PacketsScaled: 8},
		{TenantID: "t-a", Exporter: "r1", Protocol: "sflow5", TS: now.Add(-2 * time.Minute),
			SrcAddr: "10.0.0.2", DstAddr: "10.0.0.9", SrcASN: 64501, SrcASName: "OTHER-NET",
			DstASN: 64510, DstASName: "DEST-NET", SrcCountry: "CA", DstCountry: "DE",
			SrcPort: 53000, DstPort: 53, Transport: "udp",
			InIf: 1, OutIf: 2, BytesScaled: 5_000, PacketsScaled: 5},
		// outside the window
		{TenantID: "t-a", Exporter: "r1", Protocol: "netflow5", TS: now.Add(-3 * time.Hour),
			SrcAddr: "10.0.0.3", DstAddr: "10.0.0.9", BytesScaled: 99_000, PacketsScaled: 99, InIf: 1},
		// other tenant — the isolation canary
		{TenantID: "t-b", Exporter: "r1", Protocol: "netflow5", TS: now.Add(-5 * time.Minute),
			SrcAddr: "172.16.0.1", DstAddr: "172.16.0.2", BytesScaled: 1_000_000, PacketsScaled: 1000, InIf: 1},
	}
	if err := s.Insert(context.Background(), rows); err != nil {
		t.Fatalf("insert: %v", err)
	}
}

// TestMemoryTopTalkers checks every grouping plus ordering, the window filter,
// and — most importantly — that tenant-b's million-byte row never leaks.
func TestMemoryTopTalkers(t *testing.T) {
	m := NewMemory()
	seed(t, m)
	ctx := context.Background()

	top, err := m.TopTalkers(ctx, TopQuery{TenantID: "t-a", By: BySrc, Window: time.Hour, Now: now})
	if err != nil {
		t.Fatalf("top src: %v", err)
	}
	if len(top) != 2 || top[0].Key != "10.0.0.1" || top[0].Bytes != 30_000 || top[0].Flows != 3 {
		t.Fatalf("top src = %+v", top)
	}
	for _, r := range top {
		if strings.HasPrefix(r.Key, "172.16.") {
			t.Fatalf("CROSS-TENANT LEAK: %+v", r)
		}
	}

	top, _ = m.TopTalkers(ctx, TopQuery{TenantID: "t-a", By: ByDst, Window: time.Hour, Now: now})
	if top[0].Key != "10.0.0.9" || top[0].Bytes != 27_000 {
		t.Fatalf("top dst = %+v", top)
	}

	top, _ = m.TopTalkers(ctx, TopQuery{TenantID: "t-a", By: ByPair, Window: time.Hour, Now: now})
	if top[0].Key != "10.0.0.1" || top[0].Detail != "10.0.0.9" || top[0].Bytes != 22_000 {
		t.Fatalf("top pair = %+v", top)
	}

	top, _ = m.TopTalkers(ctx, TopQuery{TenantID: "t-a", By: BySrcASN, Window: time.Hour, Now: now})
	if top[0].Key != "64500" || top[0].Detail != "ACME-NET" || top[0].Bytes != 30_000 {
		t.Fatalf("top src_asn = %+v", top)
	}

	// Limit applies after ordering.
	top, _ = m.TopTalkers(ctx, TopQuery{TenantID: "t-a", By: BySrc, Window: time.Hour, Limit: 1, Now: now})
	if len(top) != 1 || top[0].Key != "10.0.0.1" {
		t.Fatalf("limit = %+v", top)
	}

	if _, err := m.TopTalkers(ctx, TopQuery{TenantID: "", By: BySrc}); err == nil {
		t.Fatal("missing tenant must error")
	}
	if _, err := m.TopTalkers(ctx, TopQuery{TenantID: "t-a", By: "bogus"}); err == nil {
		t.Fatal("bogus grouping must error")
	}
}

// TestMemoryExporterCountIsTenantScoped plants the same destination for two
// tenants, with the foreign tenant observed by more exporters. Neither the
// ranked aggregate nor its aligned series may count a foreign exporter.
func TestMemoryExporterCountIsTenantScoped(t *testing.T) {
	m := NewMemory()
	rows := []Row{
		{TenantID: "t-a", Exporter: "edge-a", Protocol: "ipfix", TS: now.Add(-2 * time.Minute), SrcAddr: "10.0.0.1", DstAddr: "203.0.113.9", BytesScaled: 100, PacketsScaled: 1},
		{TenantID: "t-a", Exporter: "edge-b", Protocol: "ipfix", TS: now.Add(-time.Minute), SrcAddr: "10.0.0.2", DstAddr: "203.0.113.9", BytesScaled: 200, PacketsScaled: 2},
		{TenantID: "t-b", Exporter: "foreign-a", Protocol: "ipfix", TS: now.Add(-3 * time.Minute), SrcAddr: "192.0.2.1", DstAddr: "203.0.113.9", BytesScaled: 1_000, PacketsScaled: 10},
		{TenantID: "t-b", Exporter: "foreign-b", Protocol: "ipfix", TS: now.Add(-2 * time.Minute), SrcAddr: "192.0.2.2", DstAddr: "203.0.113.9", BytesScaled: 2_000, PacketsScaled: 20},
		{TenantID: "t-b", Exporter: "foreign-c", Protocol: "ipfix", TS: now.Add(-time.Minute), SrcAddr: "192.0.2.3", DstAddr: "203.0.113.9", BytesScaled: 3_000, PacketsScaled: 30},
	}
	if err := m.Insert(context.Background(), rows); err != nil {
		t.Fatal(err)
	}

	q := TopQuery{
		TenantID: "t-a",
		By:       ByDst,
		Window:   time.Hour,
		Bucket:   5 * time.Minute,
		Now:      now,
	}
	top, err := m.TopTalkers(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(top) != 1 || top[0].Key != "203.0.113.9" || top[0].ExporterCount != 2 {
		t.Fatalf("tenant A observation multiplicity = %+v, want only its 2 exporters", top)
	}
	series, err := m.TopSeries(context.Background(), q, top)
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 1 || series[0].ExporterCount != 2 {
		t.Fatalf("tenant A series observation multiplicity = %+v, want only its 2 exporters", series)
	}

	foreign, err := m.TopTalkers(context.Background(), TopQuery{
		TenantID: "t-b",
		By:       ByDst,
		Window:   time.Hour,
		Now:      now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(foreign) != 1 || foreign[0].ExporterCount != 3 {
		t.Fatalf("planted foreign oracle is invalid: %+v", foreign)
	}
}

func TestMemoryExporterCountExcludesMissingIdentities(t *testing.T) {
	m := NewMemory()
	rows := []Row{
		{TenantID: "t-a", Exporter: "", Protocol: "ipfix", TS: now.Add(-2 * time.Minute), SrcAddr: "10.0.0.1", DstAddr: "203.0.113.8", BytesScaled: 100, PacketsScaled: 1},
		{TenantID: "t-a", Exporter: "   ", Protocol: "ipfix", TS: now.Add(-time.Minute), SrcAddr: "10.0.0.2", DstAddr: "203.0.113.8", BytesScaled: 200, PacketsScaled: 2},
		{TenantID: "t-a", Exporter: "edge-a", Protocol: "ipfix", TS: now.Add(-2 * time.Minute), SrcAddr: "10.0.0.3", DstAddr: "203.0.113.9", BytesScaled: 300, PacketsScaled: 3},
		{TenantID: "t-a", Exporter: " edge-a ", Protocol: "ipfix", TS: now.Add(-time.Minute), SrcAddr: "10.0.0.4", DstAddr: "203.0.113.9", BytesScaled: 400, PacketsScaled: 4},
	}
	if err := m.Insert(context.Background(), rows); err != nil {
		t.Fatal(err)
	}

	q := TopQuery{
		TenantID: "t-a",
		By:       ByDst,
		Window:   time.Hour,
		Bucket:   5 * time.Minute,
		Now:      now,
	}
	top, err := m.TopTalkers(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]uint64, len(top))
	for _, row := range top {
		counts[row.Key] = row.ExporterCount
	}
	if counts["203.0.113.8"] != 0 || counts["203.0.113.9"] != 1 {
		t.Fatalf("missing/canonical exporter counts = %v, want unavailable=0 edge-a=1", counts)
	}
	series, err := m.TopSeries(context.Background(), q, top)
	if err != nil {
		t.Fatal(err)
	}
	for _, point := range series {
		if point.ExporterCount != counts[point.Key] {
			t.Fatalf("series/top exporter counts disagree: point=%+v top=%v", point, counts)
		}
	}
}

func TestMemoryFlowFacetsFiltersAndSeries(t *testing.T) {
	m := NewMemory()
	seed(t, m)
	ctx := context.Background()

	tests := []struct {
		by      string
		wantKey string
	}{
		{ByASName, "DEST-NET"},
		{BySrcCountry, "US"},
		{ByDstCountry, "DE"},
		{ByPort, "443"},
		{ByProtocol, "netflow5"},
		{ByExporter, "r1"},
	}
	for _, tc := range tests {
		t.Run(tc.by, func(t *testing.T) {
			top, err := m.TopTalkers(ctx, TopQuery{
				TenantID: "t-a", By: tc.by, Window: time.Hour, Now: now,
			})
			if err != nil {
				t.Fatalf("top %s: %v", tc.by, err)
			}
			if len(top) == 0 || top[0].Key != tc.wantKey {
				t.Fatalf("top %s = %+v, want leading key %q", tc.by, top, tc.wantKey)
			}
		})
	}

	q := TopQuery{
		TenantID: "t-a",
		By:       ByDst,
		Window:   time.Hour,
		Bucket:   time.Minute,
		Now:      now,
		Filters: []Filter{
			{Field: FilterSrc, Value: "10.0.0.1"},
			{Field: FilterProtocol, Value: "ipfix"},
			{Field: FilterPort, Value: "8443"},
		},
	}
	top, err := m.TopTalkers(ctx, q)
	if err != nil {
		t.Fatalf("filtered top: %v", err)
	}
	if len(top) != 1 || top[0].Key != "10.0.0.8" || top[0].Bytes != 8_000 {
		t.Fatalf("stacked filters = %+v", top)
	}
	series, err := m.TopSeries(ctx, q, top)
	if err != nil {
		t.Fatalf("filtered series: %v", err)
	}
	if len(series) != 1 || series[0].Key != "10.0.0.8" || series[0].Bytes != 8_000 {
		t.Fatalf("filtered series = %+v", series)
	}
	for _, point := range series {
		if strings.HasPrefix(point.Key, "172.16.") {
			t.Fatalf("CROSS-TENANT SERIES LEAK: %+v", point)
		}
	}

	for _, invalid := range []Filter{
		{Field: FilterField("tenant_id"), Value: "t-b"},
		{Field: FilterPort, Value: "70000"},
		{Field: FilterGroupPort, Value: "0"},
		{Field: FilterSrcASN, Value: "not-an-asn"},
		{Field: FilterExporter, Value: ""},
	} {
		if _, err := m.TopTalkers(ctx, TopQuery{
			TenantID: "t-a", By: BySrc, Filters: []Filter{invalid},
		}); err == nil {
			t.Fatalf("invalid filter accepted: %+v", invalid)
		}
	}
}

func TestMemoryGroupingKeyFiltersExcludeOtherEndpointAndTenant(t *testing.T) {
	at := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	m := NewMemory()
	if err := m.Insert(context.Background(), []Row{
		{
			TenantID: "tenant-a", Exporter: "expected", Protocol: "ipfix", TS: at.Add(-time.Minute),
			SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2", SrcASName: "SOURCE",
			DstASName: "TARGET", SrcPort: 50000, DstPort: 443, BytesScaled: 100, PacketsScaled: 1,
		},
		{
			TenantID: "tenant-a", Exporter: "wrong-as-side", Protocol: "ipfix", TS: at.Add(-time.Minute),
			SrcAddr: "10.0.0.3", DstAddr: "10.0.0.4", SrcASName: "TARGET",
			DstASName: "OTHER", SrcPort: 50001, DstPort: 8443, BytesScaled: 90, PacketsScaled: 1,
		},
		{
			TenantID: "tenant-a", Exporter: "wrong-port-side", Protocol: "ipfix", TS: at.Add(-time.Minute),
			SrcAddr: "10.0.0.5", DstAddr: "10.0.0.6", SrcASName: "SOURCE",
			DstASName: "OTHER", SrcPort: 443, DstPort: 9443, BytesScaled: 80, PacketsScaled: 1,
		},
		{
			TenantID: "tenant-b", Exporter: "foreign", Protocol: "ipfix", TS: at.Add(-time.Minute),
			SrcAddr: "192.0.2.1", DstAddr: "192.0.2.2", SrcASName: "SOURCE",
			DstASName: "TARGET", SrcPort: 50002, DstPort: 443, BytesScaled: 10_000, PacketsScaled: 100,
		},
	}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		exact       Filter
		legacy      Filter
		legacyExtra string
	}{
		{
			name: "as_name", exact: Filter{Field: FilterGroupASName, Value: "TARGET"},
			legacy: Filter{Field: FilterASName, Value: "TARGET"}, legacyExtra: "wrong-as-side",
		},
		{
			name: "port", exact: Filter{Field: FilterGroupPort, Value: "443"},
			legacy: Filter{Field: FilterPort, Value: "443"}, legacyExtra: "wrong-port-side",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exactQuery := TopQuery{
				TenantID: "tenant-a", By: ByExporter, Window: time.Hour, Now: at,
				Filters: []Filter{tc.exact},
			}
			rows, err := m.TopTalkers(context.Background(), exactQuery)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0].Key != "expected" {
				t.Fatalf("exact contributors = %+v, want only expected", rows)
			}
			series, err := m.TopSeries(context.Background(), exactQuery, rows)
			if err != nil {
				t.Fatal(err)
			}
			if len(series) != 1 || series[0].Key != "expected" {
				t.Fatalf("exact contributor series = %+v, want only expected", series)
			}

			legacyQuery := exactQuery
			legacyQuery.Filters = []Filter{tc.legacy}
			legacy, err := m.TopTalkers(context.Background(), legacyQuery)
			if err != nil {
				t.Fatal(err)
			}
			if len(legacy) != 2 || legacy[0].Key != "expected" || legacy[1].Key != tc.legacyExtra {
				t.Fatalf("legacy any-side contributors = %+v", legacy)
			}
			for _, row := range append(rows, legacy...) {
				if row.Key == "foreign" {
					t.Fatalf("CROSS-TENANT CONTRIBUTOR LEAK: %+v", row)
				}
			}
		})
	}
}

// TestMemoryCapacity verifies bucket math: 22k scaled bytes in the
// -5m..-4m minute bucket region with 60s buckets -> bps = bytes*8/60.
func TestMemoryCapacity(t *testing.T) {
	m := NewMemory()
	seed(t, m)
	pts, err := m.Capacity(context.Background(), CapacityQuery{
		TenantID: "t-a", Window: time.Hour, Bucket: time.Minute, Now: now})
	if err != nil {
		t.Fatalf("capacity: %v", err)
	}
	if len(pts) != 4 {
		t.Fatalf("points = %d (%+v)", len(pts), pts)
	}
	first := pts[0]
	if first.Exporter != "r1" || first.Iface != 1 {
		t.Fatalf("first point identity = %+v", first)
	}
	if want := float64(10_000) * 8 / 60; first.Bps != want {
		t.Fatalf("bps = %v, want %v", first.Bps, want)
	}
	// Direction=out groups by out_if.
	pts, _ = m.Capacity(context.Background(), CapacityQuery{
		TenantID: "t-a", Direction: "out", Window: time.Hour, Bucket: time.Minute, Now: now})
	if pts[0].Iface != 2 {
		t.Fatalf("out iface = %+v", pts[0])
	}
}

func TestMemoryFlowDedupRedelivery(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	base := Row{
		TenantID: "t-a", AgentID: "agent-1", Exporter: "r1", ObsDomain: 10,
		Protocol: "netflow5", TS: now.Add(-time.Minute),
		SrcAddr: "10.0.0.1", DstAddr: "10.0.0.9", SrcPort: 12345, DstPort: 443,
		Transport: "tcp", InIf: 1, OutIf: 2,
		Bytes: 1_000, Packets: 10, BytesScaled: 1_000, PacketsScaled: 10,
	}
	distinct := base
	distinct.TS = base.TS.Add(30 * time.Second)
	distinct.DstPort = 8443
	distinct.Bytes = 2_000
	distinct.Packets = 20
	distinct.BytesScaled = 2_000
	distinct.PacketsScaled = 20

	if err := m.Insert(ctx, []Row{base, base, distinct}); err != nil {
		t.Fatalf("insert redelivery: %v", err)
	}
	if got := m.Len(); got != 2 {
		t.Fatalf("memory store retained %d rows, want two unique rows", got)
	}

	top, err := m.TopTalkers(ctx, TopQuery{TenantID: "t-a", By: BySrc, Window: time.Hour, Now: now})
	if err != nil {
		t.Fatalf("top talkers: %v", err)
	}
	if len(top) != 1 || top[0].Key != "10.0.0.1" || top[0].Bytes != 3_000 || top[0].Packets != 30 || top[0].Flows != 2 {
		t.Fatalf("redelivered row was aggregated instead of deduped: %+v", top)
	}

	pts, err := m.Capacity(ctx, CapacityQuery{
		TenantID: "t-a", Window: time.Hour, Bucket: time.Minute, Now: now,
	})
	if err != nil {
		t.Fatalf("capacity: %v", err)
	}
	if len(pts) != 1 {
		t.Fatalf("capacity points = %+v, want one bucket", pts)
	}
	if want := float64(3_000) * 8 / 60; pts[0].Bps != want {
		t.Fatalf("capacity bps = %v, want %v", pts[0].Bps, want)
	}

	var buf bytes.Buffer
	exported, err := m.ExportTenant(ctx, "t-a", &buf)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if exported != 2 || strings.Count(buf.String(), "\n") != 2 {
		t.Fatalf("exported %d rows (%q), want two unique rows", exported, buf.String())
	}
}

func TestInsertRejectsTenantlessRowsBeforeWriteOrRoute(t *testing.T) {
	ctx := context.Background()

	m := NewMemory()
	if err := m.Insert(ctx, []Row{
		{TenantID: "t-a", Exporter: "r1", TS: now, SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2"},
		{Exporter: "r2", TS: now, SrcAddr: "192.0.2.1", DstAddr: "192.0.2.2"},
	}); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("memory tenantless insert error = %v, want ErrNoTenant", err)
	}
	if got := m.Len(); got != 0 {
		t.Fatalf("memory insert wrote %d rows from a mixed tenantless batch; want fail-closed zero writes", got)
	}

	routed := false
	c := (&ClickHouse{}).WithRouter(func(context.Context, string) (Target, error) {
		routed = true
		return Target{}, nil
	})
	if err := c.Insert(ctx, []Row{{Exporter: "r1", TS: now}}); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("clickhouse tenantless insert error = %v, want ErrNoTenant", err)
	}
	if routed {
		t.Fatal("clickhouse insert routed a tenantless row; want reject before routing")
	}
}

func TestMemoryFlowDedupEvictionAllowsReinsert(t *testing.T) {
	m := NewMemory()
	m.max = 1
	ctx := context.Background()
	a := Row{
		TenantID: "t-a", AgentID: "agent-1", Exporter: "r1", ObsDomain: 10,
		Protocol: "netflow5", TS: now.Add(-time.Minute),
		SrcAddr: "10.0.0.1", DstAddr: "10.0.0.9", SrcPort: 12345, DstPort: 443,
		InIf: 1, OutIf: 2, Bytes: 1_000, Packets: 10, BytesScaled: 1_000, PacketsScaled: 10,
	}
	b := a
	b.SrcAddr = "10.0.0.2"
	b.Bytes = 2_000
	b.Packets = 20
	b.BytesScaled = 2_000
	b.PacketsScaled = 20

	if err := m.Insert(ctx, []Row{a}); err != nil {
		t.Fatalf("insert a: %v", err)
	}
	if err := m.Insert(ctx, []Row{b}); err != nil {
		t.Fatalf("insert b: %v", err)
	}
	if err := m.Insert(ctx, []Row{a}); err != nil {
		t.Fatalf("reinsert evicted a: %v", err)
	}
	if got := m.Len(); got != 1 {
		t.Fatalf("memory store retained %d rows, want FIFO bound of one", got)
	}

	top, err := m.TopTalkers(ctx, TopQuery{TenantID: "t-a", By: BySrc, Window: time.Hour, Now: now})
	if err != nil {
		t.Fatalf("top talkers: %v", err)
	}
	if len(top) != 1 || top[0].Key != "10.0.0.1" || top[0].Bytes != 1_000 || top[0].Flows != 1 {
		t.Fatalf("evicted row key stayed stuck in seen map: %+v", top)
	}
}

// TestAnomalyDetection: a flat 8-bucket baseline then a 10x spike in the last
// bucket must flag exactly that interface; a steady one must not.
func TestAnomalyDetection(t *testing.T) {
	m := NewMemory()
	var rows []Row
	for i := 9; i >= 0; i-- {
		ts := now.Add(-time.Duration(i) * time.Minute)
		spike := uint64(75_000) // ~10 kbps at 60s buckets
		if i == 0 {
			spike = 750_000 // 10x in the bucket under test
		}
		rows = append(rows,
			Row{TenantID: "t-a", Exporter: "r1", InIf: 1, TS: ts, BytesScaled: spike, PacketsScaled: 10},
			Row{TenantID: "t-a", Exporter: "r1", InIf: 2, TS: ts, BytesScaled: 75_000, PacketsScaled: 10},
		)
	}
	if err := m.Insert(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	an, err := m.Anomalies(context.Background(), AnomalyQuery{
		TenantID: "t-a", Window: 10 * time.Minute, Bucket: time.Minute, Now: now.Add(30 * time.Second)})
	if err != nil {
		t.Fatalf("anomalies: %v", err)
	}
	if len(an) != 1 {
		t.Fatalf("anomalies = %+v, want exactly the spiking iface", an)
	}
	if an[0].Iface != 1 || an[0].CurrentBps <= an[0].BaselineBps {
		t.Fatalf("anomaly = %+v", an[0])
	}
	if an[0].Model != "local-zscore-v1" {
		t.Fatalf("model = %q, want local-zscore-v1", an[0].Model)
	}
	if an[0].TrainingWindow.Samples != 9 || an[0].TrainingWindow.Start.IsZero() || an[0].TrainingWindow.End.IsZero() {
		t.Fatalf("training window = %+v", an[0].TrainingWindow)
	}
	if len(an[0].FeatureCitations) == 0 {
		t.Fatalf("missing feature citations: %+v", an[0])
	}
	if an[0].Features["flow.bps"] <= an[0].BaselineBps {
		t.Fatalf("features did not carry the current flow vector: %+v", an[0].Features)
	}
	// Below MinBps nothing is flagged even with a big relative jump.
	an, _ = m.Anomalies(context.Background(), AnomalyQuery{
		TenantID: "t-a", Window: 10 * time.Minute, Bucket: time.Minute,
		MinBps: 1e12, Now: now.Add(30 * time.Second)})
	if len(an) != 0 {
		t.Fatalf("MinBps floor ignored: %+v", an)
	}
}

// TestClickHouseSQLTenantGuard pins the generated SQL: every query must filter
// tenant_id first (the cross-tenant guard for the pooled store) — and the
// tenant must travel as a BOUND PARAMETER (SEC-005/TENANT-108): an
// injection-shaped tenant id never appears in the SQL text, only in params.
func TestClickHouseSQLTenantGuard(t *testing.T) {
	const inj = "t-a'; DROP TABLE x--"
	tq := TopQuery{TenantID: inj, By: ByPair, Window: time.Hour, Limit: 5, Now: now}
	if err := tq.normalize(); err != nil {
		t.Fatal(err)
	}
	sql, params := topSQL(tq, sharedFlowsTable)
	if !strings.Contains(sql, "WHERE tenant_id={tenant:String}") {
		t.Fatalf("tenant must be a leading bound parameter: %s", sql)
	}
	if strings.Contains(sql, inj) || strings.Contains(sql, "DROP TABLE") {
		t.Fatalf("INJECTION: raw tenant value leaked into the SQL text: %s", sql)
	}
	if params["tenant"] != inj {
		t.Fatalf("tenant param = %q, want the raw (unescaped) value", params["tenant"])
	}
	if params["since"] == "" || params["until"] == "" {
		t.Fatalf("time bounds must be bound parameters: %v", params)
	}
	if !strings.Contains(sql, "GROUP BY k, d") || !strings.Contains(sql, "LIMIT 5") {
		t.Fatalf("pair grouping/limit missing: %s", sql)
	}
	const exporterCountSQL = "uniqExactIf(trimBoth(exporter), notEmpty(trimBoth(exporter))) AS e"
	if !strings.Contains(sql, exporterCountSQL) {
		t.Fatalf("top-talkers SQL must count only non-empty distinct exporters inside the scoped aggregate: %s", sql)
	}

	cq := CapacityQuery{TenantID: "t-a", Exporter: "r1'; --", Direction: "out", Window: time.Hour, Bucket: 5 * time.Minute, Now: now}
	if err := cq.normalize(); err != nil {
		t.Fatal(err)
	}
	csql, cparams := capacitySQL(cq, sharedFlowsTable)
	for _, want := range []string{"WHERE tenant_id={tenant:String}", "out_if AS iface", "INTERVAL 300 second", "exporter={exporter:String}"} {
		if !strings.Contains(csql, want) {
			t.Fatalf("capacity sql missing %q: %s", want, csql)
		}
	}
	if strings.Contains(csql, "r1'") {
		t.Fatalf("INJECTION: raw exporter value leaked into the SQL text: %s", csql)
	}
	if cparams["tenant"] != "t-a" || cparams["exporter"] != "r1'; --" {
		t.Fatalf("capacity params = %v, want raw values bound", cparams)
	}
	// No exporter filter → no exporter param, no dangling placeholder.
	nsql, nparams := capacitySQL(CapacityQuery{TenantID: "t-a", Window: time.Hour, Bucket: time.Minute, Now: now}, sharedFlowsTable)
	if strings.Contains(nsql, "{exporter") {
		t.Fatalf("unbound exporter placeholder: %s", nsql)
	}
	if _, ok := nparams["exporter"]; ok {
		t.Fatalf("exporter param without a filter: %v", nparams)
	}

	// ASN grouping excludes the zero ASN and carries the org name.
	aq := TopQuery{TenantID: "t-a", By: BySrcASN, Window: time.Hour, Now: now}
	_ = aq.normalize()
	asql, _ := topSQL(aq, sharedFlowsTable)
	if !strings.Contains(asql, "src_asn != 0") || !strings.Contains(asql, "src_as_name AS d") {
		t.Fatalf("asn sql = %s", asql)
	}

	// Facet values are bound even when they contain SQL injection syntax.
	fq := TopQuery{
		TenantID: "t-a", By: ByProtocol, Window: time.Hour, Now: now,
		Filters: []Filter{
			{Field: FilterProtocol, Value: "tcp' OR 1=1 --"},
			{Field: FilterPort, Value: "443"},
		},
	}
	if err := fq.normalize(); err != nil {
		t.Fatal(err)
	}
	fsql, fparams := topSQL(fq, sharedFlowsTable)
	if strings.Contains(fsql, "OR 1=1") || strings.Contains(fsql, "tcp'") {
		t.Fatalf("INJECTION: filter value leaked into SQL: %s", fsql)
	}
	for _, want := range []string{
		"protocol={filter_0:String}",
		"(src_port={filter_1:UInt16} OR dst_port={filter_1:UInt16})",
	} {
		if !strings.Contains(fsql, want) {
			t.Fatalf("filtered SQL missing %q: %s", want, fsql)
		}
	}
	if fparams["filter_0"] != "tcp' OR 1=1 --" || fparams["filter_1"] != "443" {
		t.Fatalf("filter params = %v", fparams)
	}

	gq := TopQuery{
		TenantID: "t-a", By: ByExporter, Window: time.Hour, Now: now,
		Filters: []Filter{
			{Field: FilterGroupASName, Value: "DEST-NET"},
			{Field: FilterGroupPort, Value: "443"},
		},
	}
	if err := gq.normalize(); err != nil {
		t.Fatal(err)
	}
	gsql, gparams := topSQL(gq, sharedFlowsTable)
	for _, want := range []string{
		"WHERE tenant_id={tenant:String}",
		"if(dst_as_name != '', dst_as_name, src_as_name)={filter_0:String}",
		"if(dst_port != 0, dst_port, src_port)={filter_1:UInt16}",
	} {
		if !strings.Contains(gsql, want) {
			t.Fatalf("group-key SQL missing %q: %s", want, gsql)
		}
	}
	if gparams["tenant"] != "t-a" ||
		gparams["filter_0"] != "DEST-NET" ||
		gparams["filter_1"] != "443" {
		t.Fatalf("group-key params = %v", gparams)
	}

	seriesSQL, seriesParams := topSeriesSQL(fq, sharedFlowsTable, []TopRow{
		{Key: "tcp' OR 1=1 --"},
	})
	if strings.Contains(seriesSQL, "tcp'") ||
		!strings.Contains(seriesSQL, "WHERE tenant_id={tenant:String}") ||
		!strings.Contains(seriesSQL, "INTERVAL 180 second") ||
		!strings.Contains(seriesSQL, exporterCountSQL) {
		t.Fatalf("series SQL lost binding/scope/bucket contract: %s", seriesSQL)
	}
	if seriesParams["tenant"] != "t-a" || seriesParams["series_key_0"] != "tcp' OR 1=1 --" {
		t.Fatalf("series params = %v", seriesParams)
	}
}

// TestChParamsBindingURL pins the transport contract: bound values travel as
// param_<name> HTTP parameters (server-side binding), URL-encoded, and never
// inside the query= SQL text.
func TestChParamsBindingURL(t *testing.T) {
	const inj = "x' OR '1'='1"
	p := chParams{"tenant": inj}
	qs := p.qs()
	if !strings.Contains(qs, "&param_tenant=") {
		t.Fatalf("param_tenant missing: %s", qs)
	}
	if !strings.Contains(qs, "x%27+OR+%271%27%3D%271") {
		t.Fatalf("param value not URL-encoded: %s", qs)
	}
	if (chParams)(nil).qs() != "" || (chParams{}).qs() != "" {
		t.Fatal("empty params must render no suffix")
	}
}

// TestChValidUser pins the DDL identifier guard (identifiers cannot be bound,
// so they are validated, fail closed).
func TestChValidUser(t *testing.T) {
	for _, ok := range []string{"default", "probectl_reader", "tenant-a-123", "A1"} {
		if err := chValidUser(ok); err != nil {
			t.Fatalf("valid user %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a b", "x;DROP USER y", "a'b", "-lead", "x" + strings.Repeat("y", 70)} {
		if err := chValidUser(bad); err == nil {
			t.Fatalf("malformed user %q accepted", bad)
		}
	}
}

// TestDDLShape pins the schema's tenancy + retention properties.
func TestDDLShape(t *testing.T) {
	for _, want := range []string{
		"PARTITION BY (tenant_id, toYYYYMMDD(ts))",
		"ORDER BY (tenant_id, ts, exporter",
		"IF NOT EXISTS",
	} {
		if !strings.Contains(createFlowsDDL(sharedFlowsTable), want) {
			t.Errorf("DDL missing %q", want)
		}
	}
}

// TestStoreModeSelection covers the factory.
func TestStoreModeSelection(t *testing.T) {
	if s, err := New("", "", 0); err != nil || s == nil {
		t.Fatalf("default mode: %v", err)
	}
	if _, err := New("clickhouse", "", 0); err == nil {
		t.Fatal("clickhouse without URL must error")
	}
	if _, err := New("bogus", "", 0); err == nil {
		t.Fatal("unknown mode must error")
	}
}

// U-026 defense in depth: every tenant-keyed ClickHouse operation refuses an
// empty tenant before any SQL is built, and the query builders pin the
// tenant predicate at the head of the WHERE.
func TestClickHouseRefusesUnscopedQueries(t *testing.T) {
	c := &ClickHouse{base: "http://127.0.0.1:1"} // never dialed: refusals are pre-flight
	ctx := context.Background()
	if _, err := c.TopTalkers(ctx, TopQuery{By: BySrc, Window: time.Hour, Now: time.Now(), Limit: 5}); err != ErrNoTenant {
		t.Fatalf("TopTalkers unscoped: %v", err)
	}
	if _, err := c.Capacity(ctx, CapacityQuery{Window: time.Hour, Now: time.Now()}); err != ErrNoTenant {
		t.Fatalf("Capacity unscoped: %v", err)
	}
	if _, err := c.DeleteTenant(ctx, ""); err != ErrNoTenant {
		t.Fatalf("DeleteTenant unscoped: %v", err)
	}
	if err := c.DeleteTenantBefore(ctx, "", time.Now()); err != ErrNoTenant {
		t.Fatalf("DeleteTenantBefore unscoped: %v", err)
	}
	if _, err := c.ExportTenant(ctx, "", io.Discard); err != ErrNoTenant {
		t.Fatalf("ExportTenant unscoped: %v", err)
	}
	// Builders pin the predicate at the head of the WHERE, value bound.
	sql, params := topSQL(TopQuery{TenantID: "tX", By: BySrc, Window: time.Hour, Now: time.Now(), Limit: 5}, sharedFlowsTable)
	if !strings.Contains(sql, "WHERE tenant_id={tenant:String}") || params["tenant"] != "tX" {
		t.Fatalf("top SQL lost the leading bound tenant predicate: %s %v", sql, params)
	}
}
