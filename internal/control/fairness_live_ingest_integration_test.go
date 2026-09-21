// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/fairness"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// The real-stack receipt for tenant fairness (F57). The gap: the bound proof
// "stores two-tenant policies and calls Gate.AdmitN directly; no live
// ingestion/query consumers or fairness API, CLI, and UI outcome is exercised."
//
// Calling AdmitN directly tests a token bucket. It cannot test the thing fairness
// EXISTS for, which is that one tenant flooding the ingest path does not cost
// another tenant its throughput — that property only appears when a real consumer
// pulls a shared topic and applies the gate per record.
//
// So: two tenants with policies stored in Postgres through the production
// PolicySource, a gate built the way cmd/probectl-control builds it, the real
// pipeline.Consumer on a real Kafka, and the same flood published for both. The
// tenant with the tight ceiling must be shed; the tenant with the generous one
// must not lose a single record to its neighbor's overrun. Read back through GET
// /v1/fairness and `probectl fairness status`.
func TestFairnessShedsTheFloodingTenantAndSparesItsNeighbour(t *testing.T) {
	brokers := testsupport.KafkaBrokers()
	if len(brokers) == 0 {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_KAFKA not set — the fairness receipt needs a real bus")
	}
	ctx := context.Background()

	b, err := bus.NewKafka(brokers, 0, kgo.AllowAutoTopicCreation())
	if err != nil {
		t.Fatalf("kafka: %v", err)
	}
	defer b.Close()

	srv, db := setupAPIServerWithLatest(t, nil)
	noisy := freshTenant(t, db, "fairNoisy")
	quiet := freshTenant(t, db, "fairQuiet")

	// Each tenant's agent must be REGISTERED in that tenant's own registry
	// partition. The result lane refuses to run without a tenant binding at all
	// (TENANT-101, fail closed: without one the payload's tenant claim would be
	// authoritative), so this receipt exercises the registry-verified lane rather
	// than a lane with verification switched off.
	stamp := time.Now().UnixNano()
	agentNoisy := uuid(t)
	agentQuiet := uuid(t)
	registerFairnessAgent(t, db, noisy, agentNoisy)
	registerFairnessAgent(t, db, quiet, agentQuiet)

	// Policies stored in Postgres through the PRODUCTION source, not injected.
	store := fairness.NewPGStore(db.Pool())
	if err := store.Upsert(ctx, noisy, fairness.Policy{ResultsPerSec: 1, BurstSeconds: 1}, "fairness-receipt"); err != nil {
		t.Fatalf("store noisy policy: %v", err)
	}
	if err := store.Upsert(ctx, quiet, fairness.Policy{ResultsPerSec: 10_000, BurstSeconds: 10}, "fairness-receipt"); err != nil {
		t.Fatalf("store quiet policy: %v", err)
	}
	// Built the way cmd/probectl-control/fairness_gate.go builds it.
	gate := fairness.NewGate(fairness.Policy{ResultsPerSec: 10_000, BurstSeconds: 10}, store)
	h := srv.WithFairness(gate).Handler()

	// A stored override is applied EVENTUALLY, not instantly: the gate enforces
	// defaults on first sight of a tenant and fetches the override asynchronously
	// off the hot path (a deliberate design — the ingest path must not wait on
	// Postgres). So the receipt waits for each policy to be the effective one
	// before flooding; otherwise it measures the default ceiling and concludes,
	// wrongly, that fairness does not enforce. Asserting this here also pins the
	// property, which an operator changing a quota needs to know.
	awaitEffectivePolicy(t, h, noisy, 1)
	awaitEffectivePolicy(t, h, quiet, 10_000)

	const flood = 40
	// Produce before subscribing: producing creates the topic on a fresh broker,
	// and the per-run group below reads from the earliest offset.
	for i := 0; i < flood; i++ {
		publishProto(ctx, t, b, bus.NetworkResultsTopic, noisy, fairnessResult(noisy, agentNoisy, i))
		publishProto(ctx, t, b, bus.NetworkResultsTopic, quiet, fairnessResult(quiet, agentQuiet, i))
	}

	// The real result consumer with the real gate. A counting writer stands in for
	// the time-series backend only — what is under test is which records the GATE
	// admits, and the writer is downstream of that decision.
	writer := &countingTSDB{}
	consumer := pipeline.NewConsumer(b, writer, fmt.Sprintf("fairness-receipt-%d", stamp), quietLog()).
		WithTenantBinding(pipeline.NewRegistryBinding(db.Pool())).
		WithFairness(gate)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- consumer.Run(runCtx) }()

	// The quiet tenant must receive every record it sent.
	quietSnap := awaitFairnessAdmitted(t, h, quiet, flood, runErr)
	noisySnap := fairnessSnapshot(t, h, noisy)
	// Give the noisy tenant's records time to be decided too, so "shed" is a
	// measurement and not a race against ingestion.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && shedCalls(noisySnap) == 0 {
		time.Sleep(250 * time.Millisecond)
		noisySnap = fairnessSnapshot(t, h, noisy)
	}

	if got := shedCalls(noisySnap); got == 0 {
		t.Errorf("the flooding tenant (1 result/sec, burst 1) was never shed after %d records: %+v", flood, noisySnap.Ingest)
	}
	// The whole point: the neighbor is untouched.
	if got := shedCalls(quietSnap); got != 0 {
		t.Errorf("the quiet tenant lost %d calls to its neighbor's flood — fairness is not isolating", got)
	}
	if got := admittedCalls(quietSnap); got != flood {
		t.Errorf("the quiet tenant had %d of %d records admitted", got, flood)
	}
	// And the two tenants must not be reading each other's accounting.
	if admittedCalls(noisySnap) >= flood {
		t.Errorf("the flooding tenant reports %d admitted of %d, which is its neighbor's number", admittedCalls(noisySnap), flood)
	}
	if noisySnap.Policy.ResultsPerSec != 1 {
		t.Errorf("the flooding tenant's policy came back as %v results/sec, want the stored 1", noisySnap.Policy.ResultsPerSec)
	}
	if quietSnap.Policy.ResultsPerSec != 10_000 {
		t.Errorf("the quiet tenant's policy came back as %v results/sec, want the stored 10000", quietSnap.Policy.ResultsPerSec)
	}

	// The operator's own path.
	live := httptest.NewServer(h)
	defer live.Close()
	out, code := runCLI(t, live.URL, noisy, "fairness", "status")
	if code != 0 {
		t.Fatalf("`probectl fairness status` exited %d: %s", code, out)
	}
	if !strings.Contains(out, "shed") && !strings.Contains(out, "results_ingested") {
		t.Errorf("the CLI does not show the tenant's ingest accounting: %s", out)
	}
}

// registerFairnessAgent puts the agent in the tenant's OWN registry partition,
// through the RLS choke point, which is what the lane's binding verifies against.
func registerFairnessAgent(t *testing.T, db *store.DB, tenant, agentID string) {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, err := store.Agents{}.Register(ctx, sc, agentID, "fairness-"+agentID[:8], agentID[:8]+".test", "itest", "", []string{"http"})
		return err
	}); err != nil {
		t.Fatalf("register agent %s for %s: %v", agentID, tenant, err)
	}
}

func fairnessResult(tenant, agentID string, i int) *resultv1.Result {
	return &resultv1.Result{
		TenantId:            tenant,
		AgentId:             agentID,
		CanaryType:          "http",
		ServerAddress:       "example.test",
		ServerPort:          443,
		NetworkTransport:    "tcp",
		NetworkProtocolName: "http",
		Success:             true,
		StartTimeUnixNano:   time.Now().Add(-time.Duration(i) * time.Millisecond).UnixNano(),
		DurationNano:        int64(5 * time.Millisecond),
		Metrics:             map[string]float64{"latency_ms": float64(10 + i)},
	}
}

// countingTSDB counts what the pipeline decided to write. It is downstream of the
// fairness decision, which is what this receipt measures.
type countingTSDB struct {
	mu     sync.Mutex
	series int
}

func (c *countingTSDB) Write(_ context.Context, series []tsdb.Series) error {
	c.mu.Lock()
	c.series += len(series)
	c.mu.Unlock()
	return nil
}

func (c *countingTSDB) Close() error { return nil }

func fairnessSnapshot(t *testing.T, h http.Handler, tenant string) fairness.Snapshot {
	t.Helper()
	rec := apiReq(t, h, http.MethodGet, "/v1/fairness", tenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/fairness as %s: %d %s", tenant, rec.Code, rec.Body)
	}
	var body struct {
		Enforcing bool                         `json:"enforcing"`
		Policy    fairness.Policy              `json:"policy"`
		Ingest    map[string]fairness.Counters `json:"ingest"`
		Queries   fairness.QueryCounters       `json:"queries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode fairness: %v", err)
	}
	if !body.Enforcing {
		t.Fatal("the API reports fairness is not enforcing, so the counters below mean nothing")
	}
	return fairness.Snapshot{TenantID: tenant, Policy: body.Policy, Ingest: body.Ingest, Queries: body.Queries}
}

// The results meter specifically. Summing every meter double-counts: one result
// is metered as both a result and its bytes, so a 40-record flood reads as 80.
func admittedCalls(s fairness.Snapshot) int64 {
	return s.Ingest[fairness.MeterResults].AdmittedCalls
}

func shedCalls(s fairness.Snapshot) int64 {
	return s.Ingest[fairness.MeterResults].ShedCalls
}

// awaitEffectivePolicy waits for the stored override to become the policy the
// gate reports through /v1/fairness.
func awaitEffectivePolicy(t *testing.T, h http.Handler, tenant string, wantRPS float64) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var got float64
	for time.Now().Before(deadline) {
		snap := fairnessSnapshot(t, h, tenant)
		got = snap.Policy.ResultsPerSec
		if got == wantRPS {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("tenant %s still enforces %v results/sec after 30s, want the stored %v — the override never reached the gate", tenant, got, wantRPS)
}

// awaitFairnessAdmitted waits for the tenant to have want calls admitted. A
// timeout names the shortfall, because "the consumer never ran" and "the gate shed
// them" are different failures.
func awaitFairnessAdmitted(t *testing.T, h http.Handler, tenant string, want int64, runErr <-chan error) fairness.Snapshot {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	var last fairness.Snapshot
	for time.Now().Before(deadline) {
		select {
		case err := <-runErr:
			t.Fatalf("the result consumer stopped before admitting anything: %v", err)
		default:
		}
		last = fairnessSnapshot(t, h, tenant)
		if admittedCalls(last) >= want {
			return last
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("tenant %s had %d calls admitted and %d shed after 45s, want %d admitted — the consumer did not process the published results",
		tenant, admittedCalls(last), shedCalls(last), want)
	return last
}
