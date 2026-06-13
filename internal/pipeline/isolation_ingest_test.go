// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build isolation

// Cross-tenant INGEST-PATH suite (TENANT-105, extending Sprint 4/5) — the
// permanent isolation gate, end to end: ingest → tenant verification (real
// Postgres, RLS-scoped registry lookup) → store (real ClickHouse) → query.
//
// The DB-less unit tests in tenantverify_test.go prove the decision table with
// a FAKE binding + memory store. These prove the SAME guarantees against the
// real stores: the registry lookup that vouches for a (tenant, agent) pair is
// itself RLS-scoped (so it cannot cross tenants), and an injected record never
// lands in the victim tenant's ClickHouse partition.
//
// Runs in the cross-tenant-isolation CI job (real PG + CH); skips locally.
package pipeline

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
	"github.com/imfeelingtheagi/probectl/migrations"
)

// ── harness ────────────────────────────────────────────────────────────────

func pgPool(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("PROBECTL_DATABASE_URL")
	if dsn == "" {
		// TEST-003: in CI (PROBECTL_TEST_REQUIRE_SERVICES=1) a missing service
		// FAILS the isolation gate instead of skipping it (no vacuous green).
		testsupport.SkipOrFatal(t, "PROBECTL_DATABASE_URL not set — ingest isolation gate runs in CI")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	return pool
}

// twoTenantsOneAgent creates tenants A and B and registers agent-1 under A ONLY
// (B never knows agent-1). Returns (tenantA, tenantB) ids.
func twoTenantsOneAgent(ctx context.Context, t *testing.T, pool *pgxpool.Pool) (string, string, string) {
	t.Helper()
	tenants := store.NewTenants(pool)
	suffix := time.Now().UnixNano()
	// agents.id is a uuid column; mint a unique v4 UUID per call so repeated CI
	// runs against the shared DB never collide on the global primary key.
	agentID := fmt.Sprintf("a9000000-0000-4000-8000-%012x", suffix&0xffffffffffff)
	a, err := tenants.Create(ctx, fmt.Sprintf("iso-ing-a-%d", suffix), "Iso Ingest A")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	b, err := tenants.Create(ctx, fmt.Sprintf("iso-ing-b-%d", suffix), "Iso Ingest B")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), pool,
		func(ctx context.Context, s tenancy.Scope) error {
			_, e := (store.Agents{}).Register(ctx, s, agentID, "Agent One", "host-a", "v1", "spiffe://probectl/iso/a/"+agentID, nil)
			return e
		}); err != nil {
		t.Fatalf("register agent under A: %v", err)
	}
	return a.ID, b.ID, agentID
}

type captureWriter struct {
	mu     sync.Mutex
	series []tsdb.Series
}

func (c *captureWriter) Write(_ context.Context, s []tsdb.Series) error {
	c.mu.Lock()
	c.series = append(c.series, s...)
	c.mu.Unlock()
	return nil
}
func (c *captureWriter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.series)
}
func (c *captureWriter) Close() error { return nil }

// ── the registry lookup itself cannot cross tenants ─────────────────────────

// The verification primitive every ingest surface shares (RegistryBinding) does
// an RLS-scoped Get in the CLAIMED tenant's partition — so even though agent-1
// is a real, registered agent (under A), a lookup in B's partition cannot see
// it. This is the property that makes payload-tenant injection fail closed.
func TestRegistryBindingLookupIsTenantScoped(t *testing.T) {
	ctx := context.Background()
	pool := pgPool(ctx, t)
	defer pool.Close()
	a, b, ag := twoTenantsOneAgent(ctx, t, pool)

	binding := NewRegistryBinding(pool)
	if err := binding.Verify(ctx, a, ag); err != nil {
		t.Fatalf("agent-1 IS registered under A — must verify: %v", err)
	}
	// The injection: claim tenant B for A's agent. The RLS-scoped lookup in B
	// returns nothing → fail closed, even though agent-1 exists globally.
	if err := binding.Verify(ctx, b, ag); err == nil {
		t.Fatal("CROSS-TENANT: agent-1 verified under tenant B (RLS lookup leaked)")
	}
}

// ── flow → real ClickHouse: injection never lands in B's partition ──────────

func flowBatchMsg(tenant, agent string) bus.Message {
	batch := &flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
		TenantId: tenant, AgentId: agent, EndUnixNano: time.Now().UnixNano(),
		SourceAddress: "198.51.100.5", DestinationAddress: "203.0.113.9",
		SourcePort: 40000, DestinationPort: 443, NetworkTransport: "tcp", Bytes: 1000, Packets: 10,
	}}}
	v, _ := proto.Marshal(batch)
	return bus.Message{Key: []byte(tenant), Value: v}
}

func TestFlowIngestCrossTenantInjectionRealStores(t *testing.T) {
	ctx := context.Background()
	if os.Getenv("PROBECTL_FLOWSTORE_URL") == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL not set — flow ingest isolation gate runs in CI")
	}
	pool := pgPool(ctx, t)
	defer pool.Close()
	a, b, ag := twoTenantsOneAgent(ctx, t, pool)

	ch, err := flowstore.NewClickHouse(os.Getenv("PROBECTL_FLOWSTORE_URL"), 0)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	c := NewFlowConsumer(nil, ch, nil, testLogger()).WithTenantBinding(NewRegistryBinding(pool))
	now := time.Now().UTC()
	top := func(tenant string) int {
		rows, err := ch.TopTalkers(ctx, flowstore.TopQuery{
			TenantID: tenant, By: flowstore.BySrc, Window: time.Hour, Now: now.Add(time.Minute), Limit: 10})
		if err != nil {
			t.Fatalf("top talkers %s: %v", tenant, err)
		}
		return len(rows)
	}

	// RED TEAM: A's agent claims tenant B. Must be rejected; nothing under B.
	if err := c.handleLane(ctx, flowBatchMsg(b, ag), ""); err != nil {
		t.Fatalf("handler must drop, not error: %v", err)
	}
	if c.RejectedBatches() != 1 {
		t.Fatalf("injection not rejected: rejected=%d", c.RejectedBatches())
	}
	if n := top(b); n != 0 {
		t.Fatalf("INJECTION SUCCEEDED: %d flow rows landed under tenant B", n)
	}

	// Legit pair lands under A.
	if err := c.handleLane(ctx, flowBatchMsg(a, ag), ""); err != nil {
		t.Fatalf("legit batch: %v", err)
	}
	if n := top(a); n == 0 {
		t.Fatal("legit flow row did not land under tenant A")
	}

	// Namespaced lane bound to A, payload claims B → re-stamped to A; B stays empty.
	if err := c.handleLane(ctx, flowBatchMsg(b, ag), a); err != nil {
		t.Fatalf("lane batch: %v", err)
	}
	if n := top(b); n != 0 {
		t.Fatalf("lane override leaked %d rows to tenant B", n)
	}

	// Cleanup so repeat CI runs stay isolated (verifiable deletion, scoped).
	if _, err := ch.DeleteTenant(ctx, a); err != nil {
		t.Fatalf("cleanup A: %v", err)
	}
}

// ── device + eBPF/endpoint result surfaces: injection reaches no store ───────

func TestDeviceIngestCrossTenantInjection(t *testing.T) {
	ctx := context.Background()
	pool := pgPool(ctx, t)
	defer pool.Close()
	a, b, ag := twoTenantsOneAgent(ctx, t, pool)

	w := &captureWriter{}
	c := NewDeviceConsumer(nil, w, testLogger()).WithTenantBinding(NewRegistryBinding(pool))
	mk := func(tenant, agent string) bus.Message {
		batch := &devicev1.DeviceMetricBatch{Metrics: []*devicev1.DeviceMetric{{
			TenantId: tenant, AgentId: agent, Name: "probectl.device.if.in.octets",
			Value: 42, TimeUnixNano: time.Now().UnixNano(),
		}}}
		v, _ := proto.Marshal(batch)
		return bus.Message{Key: []byte(tenant), Value: v}
	}

	// Injection: dropped before any write.
	if err := c.handleLane(ctx, mk(b, ag), ""); err != nil {
		t.Fatalf("device handler must drop, not error: %v", err)
	}
	if c.RejectedBatches() != 1 || w.count() != 0 {
		t.Fatalf("device injection not contained: rejected=%d written=%d", c.RejectedBatches(), w.count())
	}
	// Legit pair is written.
	if err := c.handleLane(ctx, mk(a, ag), ""); err != nil {
		t.Fatalf("device legit: %v", err)
	}
	if w.count() == 0 {
		t.Fatal("legit device batch produced no write")
	}
}

func TestResultIngestCrossTenantInjection(t *testing.T) {
	ctx := context.Background()
	pool := pgPool(ctx, t)
	defer pool.Close()
	a, b, ag := twoTenantsOneAgent(ctx, t, pool)

	w := &captureWriter{}
	c := NewConsumer(nil, w, "iso-results", testLogger()).WithTenantBinding(NewRegistryBinding(pool))
	mk := func(tenant, agent string) bus.Message {
		v, _ := proto.Marshal(&resultv1.Result{TenantId: tenant, AgentId: agent, Success: true})
		return bus.Message{Key: []byte(tenant), Value: v}
	}

	// Agent-published lane (verify=true), payload claims B → rejected, no write.
	if err := c.handleLane(ctx, mk(b, ag), topicGroup{topic: bus.EndpointResultsTopic, verify: true}); err != nil {
		t.Fatalf("result handler must drop, not error: %v", err)
	}
	if c.rejectedTenant.Load() != 1 || w.count() != 0 {
		t.Fatalf("result injection not contained: rejected=%d written=%d", c.rejectedTenant.Load(), w.count())
	}
	// Legit pair on the same lane writes its series.
	if err := c.handleLane(ctx, mk(a, ag), topicGroup{topic: bus.EndpointResultsTopic, verify: true}); err != nil {
		t.Fatalf("result legit: %v", err)
	}
	if w.count() == 0 {
		t.Fatal("legit result produced no series write")
	}
	// Namespaced lane bound to A, payload claims B, A's agent → re-stamped to A
	// and written (agent must still be registered in the lane tenant).
	before := w.count()
	if err := c.handleLane(ctx, mk(b, ag), topicGroup{topic: "probectl." + a + ".endpoint.results", verify: true, laneTenant: a}); err != nil {
		t.Fatalf("result lane: %v", err)
	}
	if w.count() == before {
		t.Fatal("lane-stamped result was not written under the lane tenant")
	}
}
