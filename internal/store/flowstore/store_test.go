package flowstore

import (
	"context"
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
			InIf: 1, OutIf: 2, BytesScaled: 10_000, PacketsScaled: 10},
		{TenantID: "t-a", Exporter: "r1", Protocol: "netflow5", TS: now.Add(-4 * time.Minute),
			SrcAddr: "10.0.0.1", DstAddr: "10.0.0.9", SrcASN: 64500, SrcASName: "ACME-NET",
			InIf: 1, OutIf: 2, BytesScaled: 12_000, PacketsScaled: 12},
		{TenantID: "t-a", Exporter: "r1", Protocol: "ipfix", TS: now.Add(-3 * time.Minute),
			SrcAddr: "10.0.0.1", DstAddr: "10.0.0.8", SrcASN: 64500, SrcASName: "ACME-NET",
			InIf: 1, OutIf: 2, BytesScaled: 8_000, PacketsScaled: 8},
		{TenantID: "t-a", Exporter: "r1", Protocol: "sflow5", TS: now.Add(-2 * time.Minute),
			SrcAddr: "10.0.0.2", DstAddr: "10.0.0.9", SrcASN: 64501, SrcASName: "OTHER-NET",
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
	// Below MinBps nothing is flagged even with a big relative jump.
	an, _ = m.Anomalies(context.Background(), AnomalyQuery{
		TenantID: "t-a", Window: 10 * time.Minute, Bucket: time.Minute,
		MinBps: 1e12, Now: now.Add(30 * time.Second)})
	if len(an) != 0 {
		t.Fatalf("MinBps floor ignored: %+v", an)
	}
}

// TestClickHouseSQLTenantGuard pins the generated SQL: every query must filter
// tenant_id first (the cross-tenant guard for the pooled store) and embed the
// escaped literal.
func TestClickHouseSQLTenantGuard(t *testing.T) {
	tq := TopQuery{TenantID: "t-a'; DROP TABLE x--", By: ByPair, Window: time.Hour, Limit: 5, Now: now}
	if err := tq.normalize(); err != nil {
		t.Fatal(err)
	}
	sql := topSQL(tq, sharedFlowsTable)
	if !strings.Contains(sql, `WHERE tenant_id='t-a\'; DROP TABLE x--'`) {
		t.Fatalf("tenant literal not escaped/leading: %s", sql)
	}
	if !strings.Contains(sql, "GROUP BY k, d") || !strings.Contains(sql, "LIMIT 5") {
		t.Fatalf("pair grouping/limit missing: %s", sql)
	}

	cq := CapacityQuery{TenantID: "t-a", Exporter: "r1", Direction: "out", Window: time.Hour, Bucket: 5 * time.Minute, Now: now}
	if err := cq.normalize(); err != nil {
		t.Fatal(err)
	}
	csql := capacitySQL(cq, sharedFlowsTable)
	for _, want := range []string{"WHERE tenant_id='t-a'", "out_if AS iface", "INTERVAL 300 second", "exporter='r1'"} {
		if !strings.Contains(csql, want) {
			t.Fatalf("capacity sql missing %q: %s", want, csql)
		}
	}

	// ASN grouping excludes the zero ASN and carries the org name.
	aq := TopQuery{TenantID: "t-a", By: BySrcASN, Window: time.Hour, Now: now}
	_ = aq.normalize()
	asql := topSQL(aq, sharedFlowsTable)
	if !strings.Contains(asql, "src_asn != 0") || !strings.Contains(asql, "any(src_as_name)") {
		t.Fatalf("asn sql = %s", asql)
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
