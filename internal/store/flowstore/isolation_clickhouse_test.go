//go:build isolation

package flowstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// U-026: the cross-tenant isolation gate, extended to REAL ClickHouse. Runs
// inside `make test-isolation` when PROBECTL_FLOWSTORE_URL points at a CH
// (the ci job provides a containerized one); skips otherwise.
func chFlow(t *testing.T) *ClickHouse {
	t.Helper()
	url := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if url == "" {
		t.Skip("PROBECTL_FLOWSTORE_URL not set — ClickHouse isolation gate runs in CI")
	}
	c, err := NewClickHouse(url, 0)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	return c
}

func flowRow(tenant, src string, ts time.Time) Row {
	return Row{
		TenantID: tenant, AgentID: "a1", Exporter: "e1", Protocol: "netflow",
		TS: ts, StartTS: ts.Add(-time.Second),
		SrcAddr: src, DstAddr: "203.0.113.9", SrcPort: 40000, DstPort: 443,
		Transport: "tcp", Bytes: 1000, Packets: 10,
	}
}

func TestClickHouseCrossTenantIsolation(t *testing.T) {
	c := chFlow(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	ta := fmt.Sprintf("iso-a-%d", now.UnixNano())
	tb := fmt.Sprintf("iso-b-%d", now.UnixNano())

	if err := c.Insert(ctx, []Row{
		flowRow(ta, "198.51.100.1", now), flowRow(ta, "198.51.100.2", now),
		flowRow(tb, "192.0.2.77", now),
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	q := TopQuery{TenantID: ta, By: BySrc, Window: time.Hour, Now: now.Add(time.Minute), Limit: 10}
	rows, err := c.TopTalkers(ctx, q)
	if err != nil {
		t.Fatalf("top talkers: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("tenant A sees %d talkers, want exactly its own 2", len(rows))
	}
	for _, r := range rows {
		if r.Key == "192.0.2.77" {
			t.Fatalf("CROSS-TENANT LEAK: tenant A read tenant B's flow %+v", r)
		}
	}

	// Verifiable deletion stays scoped: erasing A leaves B intact.
	if _, err := c.DeleteTenant(ctx, ta); err != nil {
		t.Fatalf("delete tenant A: %v", err)
	}
	qb := TopQuery{TenantID: tb, By: BySrc, Window: time.Hour, Now: now.Add(time.Minute), Limit: 10}
	rows, err = c.TopTalkers(ctx, qb)
	if err != nil {
		t.Fatalf("top talkers B: %v", err)
	}
	if len(rows) != 1 || rows[0].Key != "192.0.2.77" {
		t.Fatalf("tenant B's data damaged by A's erasure: %+v", rows)
	}
}

// The DB-level row policies apply cleanly on a real server and register in
// system.row_policies (per-tenant CH users are then row-filtered to
// tenant_id = currentUser(); the service account keeps full access).
// SEC-005/TENANT-108 (Sprint 7): an injection-shaped tenant id is BOUND, not
// interpolated — against a real server it selects nothing and breaks nothing.
func TestClickHouseInjectionShapedTenantIsBound(t *testing.T) {
	c := chFlow(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	tid := fmt.Sprintf("iso-inj-%d", now.UnixNano())
	if err := c.Insert(ctx, []Row{flowRow(tid, "198.51.100.7", now)}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	defer func() { _, _ = c.DeleteTenant(ctx, tid) }()

	for _, inj := range []string{"x' OR '1'='1", tid + "' OR 1=1 --", "'; DROP TABLE " + sharedFlowsTable + " --"} {
		rows, err := c.TopTalkers(ctx, TopQuery{TenantID: inj, By: BySrc, Window: time.Hour, Now: now.Add(time.Minute), Limit: 10})
		if err != nil {
			t.Fatalf("bound injection value must be a VALID query (just matching nothing), got error: %v", err)
		}
		if len(rows) != 0 {
			t.Fatalf("INJECTION ESCAPED BINDING: %q matched %d rows", inj, len(rows))
		}
	}
	// The table survived the DROP-shaped value and the real tenant still reads.
	rows, err := c.TopTalkers(ctx, TopQuery{TenantID: tid, By: BySrc, Window: time.Hour, Now: now.Add(time.Minute), Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatalf("legit read after injection attempts: rows=%v err=%v", rows, err)
	}
}

func TestClickHouseRowPoliciesApply(t *testing.T) {
	c := chFlow(t)
	ctx := context.Background()
	if err := c.EnsureRowPolicies(ctx, "default"); err != nil {
		t.Fatalf("EnsureRowPolicies: %v", err)
	}
	out, err := c.query(ctx, "", "SELECT name FROM system.row_policies WHERE name LIKE 'probectl%'", nil)
	if err != nil {
		t.Fatalf("system.row_policies: %v", err)
	}
	if len(out) < 2 {
		t.Fatalf("row policies missing: %v", out)
	}
	// The service account (this connection) still sees its own writes.
	now := time.Now().UTC()
	tid := fmt.Sprintf("iso-rp-%d", now.UnixNano())
	if err := c.Insert(ctx, []Row{flowRow(tid, "198.51.100.9", now)}); err != nil {
		t.Fatalf("insert under policies: %v", err)
	}
	rows, err := c.TopTalkers(ctx, TopQuery{TenantID: tid, By: BySrc, Window: time.Hour, Now: now.Add(time.Minute), Limit: 5})
	if err != nil || len(rows) != 1 {
		t.Fatalf("service account blinded by its own policies: rows=%v err=%v", rows, err)
	}
}
