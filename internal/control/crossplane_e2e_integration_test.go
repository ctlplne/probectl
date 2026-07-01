// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package control

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/opendata"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
	"github.com/imfeelingtheagi/probectl/migrations"
)

// TestCrossPlaneCorrelationE2E is the full-stack execution of CLAUDE.md §8
// standing gate #2 (cross-plane correlation) and the EXC-GATE-05 epic. Where the
// unit-level TestCrossPlaneCorrelationGate exercises the correlator over a memory
// store, this drives a genuine multi-plane fault THROUGH THE REAL TRANSPORTS:
//
//	BGP analyzer  ──probectl.bgp.events────▶ Kafka ──▶ BGPIncidentConsumer ─┐
//	                                                                         ├─▶ PG correlator (RLS)
//	threat-intel  ──probectl.network.results──▶ Kafka ──▶ IOCConsumer ──────┘
//
// One tenant suffers a routing event on a prefix AND a probe to a known-bad IP
// inside that prefix. The two planes must coalesce into EXACTLY ONE incident,
// tenant-scoped, carrying ≥2 planes of evidence — proven by reading it back out
// of Postgres through the RLS choke point (tenancy.InTenant + store.Incidents).
// A decoy signal for a DIFFERENT tenant on the same address space must NOT join
// (isolation under correlation — the catastrophic failure, guardrail 1).
//
// It fails — never silently skips — under PROBECTL_TEST_REQUIRE_SERVICES=1 (the
// integration CI job), so the gate cannot pass by no-op. Locally, with no Kafka
// or Postgres, it skips cleanly.
func TestCrossPlaneCorrelationE2E(t *testing.T) {
	ctx := context.Background()

	brokers := testsupport.KafkaBrokers()
	if len(brokers) == 0 {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_KAFKA not set — cross-plane e2e needs a real bus")
	}
	pool, err := pgxpool.New(ctx, testsupport.PostgresDSN())
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Two tenants exist; the fault is tenant A's, tenant B is the isolation decoy.
	tenantA := seedTenant(t, pool, fmt.Sprintf("xplane-a-%d", time.Now().UnixNano()))
	tenantB := seedTenant(t, pool, fmt.Sprintf("xplane-b-%d", time.Now().UnixNano()))

	// A real Kafka bus (auto-create topics for the ephemeral test run).
	b, err := bus.NewKafka(brokers, 0, kgo.AllowAutoTopicCreation())
	if err != nil {
		t.Fatalf("kafka: %v", err)
	}
	defer b.Close()

	// The PG-backed correlator the production consumers write into.
	corr := BuildCorrelator(pool, 10*time.Minute, quietLog())

	// The known-bad IP lives inside the prefix the BGP event will flag, so the
	// network/threat plane and the routing plane share address space and join.
	const badIP = "203.0.113.10"
	const prefix = "203.0.113.0/24"
	ioc := opendata.NewIOCStore()
	ioc.Load([]opendata.IOC{{
		Type: opendata.IOCTypeIP, Value: badIP, Source: "feodo_tracker",
		Category: opendata.CategoryBotnetC2, Confidence: 95, License: "abuse.ch CC0",
	}})

	// Wire the two REAL production consumers onto the real bus + correlator.
	bgpConsumer := NewBGPIncidentConsumer(b, corr, quietLog())
	iocConsumer := NewIOCConsumer(b, corr, ioc, quietLog())

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = bgpConsumer.Run(runCtx) }()
	go func() { _ = iocConsumer.Run(runCtx) }()

	// Give the consumer groups a moment to join before producing.
	time.Sleep(2 * time.Second)

	now := time.Now().UTC()

	// Poison attempt — key says tenant B, payload claims tenant A. Consumers must
	// trust the authenticated bus envelope first and reject this without opening
	// a tenant A BGP-only incident or a tenant B topology/signal.
	publishProto(ctx, t, b, bus.BGPEventsTopic, tenantB, &bgpv1.BGPEvent{
		TenantId:           tenantA,
		EventType:          bgpv1.EventType_EVENT_TYPE_POSSIBLE_HIJACK,
		Severity:           bgpv1.Severity_SEVERITY_CRITICAL,
		Prefix:             "198.51.100.0/24",
		Message:            "poisoned tenant claim",
		Collector:          "rrc00",
		DetectedAtUnixNano: now.Add(-time.Minute).UnixNano(),
	})

	// Plane 1 — routing: a possible hijack of the prefix (tenant A).
	bgpEvt := &bgpv1.BGPEvent{
		TenantId:           tenantA,
		EventType:          bgpv1.EventType_EVENT_TYPE_POSSIBLE_HIJACK,
		Severity:           bgpv1.Severity_SEVERITY_CRITICAL,
		Prefix:             prefix,
		Message:            "possible hijack of " + prefix,
		Collector:          "rrc00",
		DetectedAtUnixNano: now.UnixNano(),
	}
	publishProto(ctx, t, b, bus.BGPEventsTopic, tenantA, bgpEvt)

	// Plane 2 — threat: tenant A probes the known-bad IP inside that prefix.
	publishProto(ctx, t, b, bus.NetworkResultsTopic, tenantA, &resultv1.Result{
		TenantId: tenantA, AgentId: "agent-a", CanaryType: "icmp",
		ServerAddress: badIP, StartTimeUnixNano: now.Add(time.Minute).UnixNano(),
	})

	// Decoy — tenant B hits the SAME bad IP. It must open B's own incident, never
	// join A's (cross-tenant correlation is the catastrophic failure, guardrail 1).
	publishProto(ctx, t, b, bus.NetworkResultsTopic, tenantB, &resultv1.Result{
		TenantId: tenantB, AgentId: "agent-b", CanaryType: "icmp",
		ServerAddress: badIP, StartTimeUnixNano: now.UnixNano(),
	})

	if err := b.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// Poll Postgres (through the RLS-scoped store) until tenant A's single
	// correlated incident carries both planes, or the deadline trips.
	var incA *incident.Incident
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		open := openIncidentsRLS(t, pool, tenantA)
		if len(open) > 1 {
			t.Fatalf("cross-plane fault split into %d incidents for tenant A, want exactly 1", len(open))
		}
		if len(open) == 1 {
			full := getIncidentRLS(t, pool, tenantA, open[0].ID)
			if planeCount(full) >= 2 {
				incA = full
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if incA == nil {
		t.Fatal("timed out waiting for ONE 2-plane correlated incident for tenant A")
	}

	// The incident rolls up to the worst plane's severity (critical BGP).
	if incA.Severity != incident.SeverityCritical {
		t.Errorf("incident severity = %s, want critical (max across planes)", incA.Severity)
	}
	planes := map[string]bool{}
	for _, s := range incA.Signals {
		planes[s.Plane] = true
	}
	if !planes["bgp"] || !planes["threat"] {
		t.Fatalf("incident must carry both bgp and threat planes, got %v", planes)
	}

	// Isolation: tenant B has its OWN incident, and tenant A's evidence never
	// leaked into it.
	openB := openIncidentsRLS(t, pool, tenantB)
	if len(openB) != 1 {
		t.Fatalf("tenant B should have its own 1 incident, got %d", len(openB))
	}
	if openB[0].ID == incA.ID {
		t.Fatal("tenant B's incident is the SAME row as tenant A's — cross-tenant correlation leak")
	}
}

func publishProto(ctx context.Context, t *testing.T, b bus.Bus, topic, tenant string, m proto.Message) {
	t.Helper()
	payload, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal %s: %v", topic, err)
	}
	if err := b.Publish(ctx, topic, []byte(tenant), payload); err != nil {
		t.Fatalf("publish %s: %v", topic, err)
	}
}

// openIncidentsRLS reads a tenant's incidents back through the RLS choke point —
// the same tenant-scoped path the timeline API uses — so the read is itself
// tenant-confined (a cross-tenant read returns nothing, not another tenant's row).
func openIncidentsRLS(t *testing.T, pool *pgxpool.Pool, tenant string) []incident.Incident {
	t.Helper()
	var out []incident.Incident
	err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenant)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			incs, e := store.Incidents{}.List(ctx, sc)
			out = incs
			return e
		})
	if err != nil {
		t.Fatalf("RLS list incidents: %v", err)
	}
	return out
}

func getIncidentRLS(t *testing.T, pool *pgxpool.Pool, tenant, id string) *incident.Incident {
	t.Helper()
	var out *incident.Incident
	err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenant)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			inc, e := store.Incidents{}.Get(ctx, sc, id)
			out = inc
			return e
		})
	if err != nil {
		t.Fatalf("RLS get incident: %v", err)
	}
	return out
}

func planeCount(inc *incident.Incident) int {
	planes := map[string]bool{}
	for _, s := range inc.Signals {
		planes[s.Plane] = true
	}
	return len(planes)
}

// seedTenant inserts (or reuses) a tenant row so the incident FK is satisfied.
func seedTenant(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tenants (slug, name) VALUES ($1, $1)
		 ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id::text`, slug).Scan(&id); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return id
}
