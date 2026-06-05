package fairness

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeClock is a deterministic, manually-advanced clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }
func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// memSource is a PolicySource for tests.
type memSource struct {
	mu       sync.Mutex
	policies map[string]Policy
	fail     bool
	fetches  int
}

func (m *memSource) PolicyFor(_ context.Context, tenantID string) (Policy, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fetches++
	if m.fail {
		return Policy{}, false, errors.New("policy store down")
	}
	p, ok := m.policies[tenantID]
	return p, ok, nil
}

// eventually polls until fn() is true (the async policy refresh).
func eventually(t *testing.T, fn func() bool) {
	t.Helper()
	for range 200 {
		if fn() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// TestBackpressureIsolation is the named backpressure test: tenant A's burst
// is shed at A's own bound while tenant B's traffic — arriving in the same
// instants through the same gate — is admitted in full. One tenant's burst
// is never another tenant's problem.
func TestBackpressureIsolation(t *testing.T) {
	clk := newFakeClock()
	// A is bounded to 100 results/sec with a 1-second burst (capacity 100);
	// B is unbounded (no policy, no deployment default).
	src := &memSource{policies: map[string]Policy{
		"tnA": {ResultsPerSec: 100, BurstSeconds: 1},
	}}
	g := NewGate(Policy{}, src).WithNow(clk.now)
	ctx := context.Background()
	g.EffectivePolicy(ctx, "tnA") // trigger the async fetch
	eventually(t, func() bool { return g.EffectivePolicy(ctx, "tnA").ResultsPerSec == 100 })

	// A bursts 1000 messages in one instant; B sends 50 interleaved.
	var aAdmit, aShed, bAdmit int
	for i := range 1000 {
		if g.AdmitN(ctx, "tnA", MeterResults, 1) {
			aAdmit++
		} else {
			aShed++
		}
		if i%20 == 0 {
			if g.AdmitN(ctx, "tnB", MeterResults, 1) {
				bAdmit++
			}
		}
	}
	if bAdmit != 50 {
		t.Fatalf("tenant B must be untouched by A's burst: admitted %d/50", bAdmit)
	}
	// A's admission is bounded by its burst capacity (deficit semantics allow
	// at most one extra call past zero).
	if aAdmit > 101 || aAdmit < 100 {
		t.Fatalf("tenant A's burst must be capped at its capacity: admitted %d", aAdmit)
	}
	if aShed != 1000-aAdmit {
		t.Fatalf("shed accounting: %d", aShed)
	}
	// Recovery, not punishment: a second later A has ~100 more tokens.
	clk.advance(time.Second)
	recovered := 0
	for range 200 {
		if g.AdmitN(ctx, "tnA", MeterResults, 1) {
			recovered++
		}
	}
	if recovered < 100 || recovered > 101 {
		t.Fatalf("A must recover its rate after the burst window: %d", recovered)
	}
	// The accounting surfaces all of it.
	snap := g.SnapshotTenant(ctx, "tnA")
	c := snap.Ingest[MeterResults]
	if c.ShedUnits == 0 || c.AdmittedUnits != int64(aAdmit+recovered) {
		t.Fatalf("accounting: %+v", c)
	}
}

// TestNoisyNeighborLatencySLO is the named noisy-neighbor test (the seed of
// the S48 load-test gate): a heavy tenant pushing 50× a modest tenant's
// volume through the SHARED sequential consumer must not breach the modest
// tenant's per-message latency SLO. The gate sheds the flood BEFORE the
// expensive section, so B's messages only ever wait behind bounded work.
func TestNoisyNeighborLatencySLO(t *testing.T) {
	src := &memSource{policies: map[string]Policy{
		"heavy": {ResultsPerSec: 200, BurstSeconds: 1},
	}}
	g := NewGate(Policy{}, src).WithPolicyTTL(time.Hour)
	ctx := context.Background()
	g.EffectivePolicy(ctx, "heavy")
	eventually(t, func() bool { return g.EffectivePolicy(ctx, "heavy").ResultsPerSec == 200 })

	const (
		storeWriteCost = 50 * time.Microsecond // the simulated expensive section
		totalMsgs      = 5000
		bEvery         = 50 // B sends 1 message per 50 of A's
		bLatencySLO    = 25 * time.Millisecond
	)
	var bWorst time.Duration
	var bShed, aAdmitted int
	for i := range totalMsgs {
		// The heavy tenant's message hits the shared loop.
		if g.AdmitN(ctx, "heavy", MeterResults, 1) {
			aAdmitted++
			time.Sleep(storeWriteCost) // only ADMITTED work costs anything
		}
		if i%bEvery != 0 {
			continue
		}
		// The modest tenant's message arrives now; its latency is the time
		// to get admitted and processed from this point.
		start := time.Now()
		if !g.AdmitN(ctx, "modest", MeterResults, 1) {
			bShed++
			continue
		}
		time.Sleep(storeWriteCost)
		if d := time.Since(start); d > bWorst {
			bWorst = d
		}
	}
	if bShed != 0 {
		t.Fatalf("the modest tenant must never be shed: %d", bShed)
	}
	if bWorst > bLatencySLO {
		t.Fatalf("the modest tenant's worst latency %v breached its SLO %v under a 50x neighbor", bWorst, bLatencySLO)
	}
	// The flood was genuinely bounded: a tiny fraction of 4900 made it in.
	if aAdmitted > 800 {
		t.Fatalf("the heavy tenant must be rate-bounded: admitted %d", aAdmitted)
	}
}

// TestQueryCostGuard is the named query-guard test: an over-budget tenant is
// rejected (429 at the transport) while another tenant queries freely — and
// a legitimately-busy tenant under its ceiling is NEVER falsely starved.
func TestQueryCostGuard(t *testing.T) {
	clk := newFakeClock()
	src := &memSource{policies: map[string]Policy{
		"tnA": {QueryConcurrency: 2, QueriesPerMin: 60},
	}}
	g := NewGate(Policy{}, src).WithNow(clk.now)
	ctx := context.Background()
	g.EffectivePolicy(ctx, "tnA")
	eventually(t, func() bool { return g.EffectivePolicy(ctx, "tnA").QueryConcurrency == 2 })

	// Concurrency: 2 in flight, the third rejects, release frees a slot.
	rel1, err1 := g.BeginQuery(ctx, "tnA")
	rel2, err2 := g.BeginQuery(ctx, "tnA")
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if _, err := g.BeginQuery(ctx, "tnA"); !errors.Is(err, ErrQueryConcurrency) {
		t.Fatalf("third in-flight query must reject: %v", err)
	}
	// The unbounded tenant is unaffected while A is saturated.
	relB, errB := g.BeginQuery(ctx, "tnB")
	if errB != nil {
		t.Fatalf("tenant B must not be affected: %v", errB)
	}
	relB()
	rel1()
	rel3, err3 := g.BeginQuery(ctx, "tnA")
	if err3 != nil {
		t.Fatalf("released slot must be reusable: %v", err3)
	}
	rel3()
	rel2()

	// Budget: A has already spent 3 of its 60-per-minute capacity. Spend the
	// remaining 57 back-to-back (the full-minute burst capacity), then the
	// next rejects with the budget error.
	for i := range 57 {
		rel, err := g.BeginQuery(ctx, "tnA")
		if err != nil {
			t.Fatalf("query %d within budget must admit: %v", i, err)
		}
		rel()
	}
	if _, err := g.BeginQuery(ctx, "tnA"); !errors.Is(err, ErrQueryBudget) {
		t.Fatalf("over-budget query must reject: %v", err)
	}
	// Refill restores service — bounded, not banned.
	clk.advance(2 * time.Second)
	rel, err := g.BeginQuery(ctx, "tnA")
	if err != nil {
		t.Fatalf("budget must refill: %v", err)
	}
	rel()

	// Never falsely starved: a tenant running EXACTLY at its budget rate
	// (1/s under 60/min) is admitted forever — zero rejections.
	clk.advance(time.Minute) // a fresh window
	for range 300 {
		clk.advance(time.Second)
		rel, err := g.BeginQuery(ctx, "tnA")
		if err != nil {
			t.Fatalf("a tenant at its sustained budget rate must never be rejected: %v", err)
		}
		rel()
	}
	snap := g.SnapshotTenant(ctx, "tnA")
	if snap.Queries.RejectedBudget != 1 || snap.Queries.RejectedConcurrency != 1 {
		t.Fatalf("query accounting: %+v", snap.Queries)
	}
}

// TestBatchLargerThanBurstIsNotStarved: deficit semantics — a flow batch
// bigger than the bucket capacity admits (going negative) instead of being
// permanently rejected, then the tenant pays the deficit back in time.
func TestBatchLargerThanBurstIsNotStarved(t *testing.T) {
	clk := newFakeClock()
	src := &memSource{policies: map[string]Policy{
		"tnA": {FlowEventsPerSec: 100, BurstSeconds: 1}, // capacity 100
	}}
	g := NewGate(Policy{}, src).WithNow(clk.now)
	ctx := context.Background()
	g.EffectivePolicy(ctx, "tnA")
	eventually(t, func() bool { return g.EffectivePolicy(ctx, "tnA").FlowEventsPerSec == 100 })

	if !g.AdmitN(ctx, "tnA", MeterFlowEvents, 500) {
		t.Fatal("a batch larger than burst must admit once (deficit), not starve forever")
	}
	if g.AdmitN(ctx, "tnA", MeterFlowEvents, 1) {
		t.Fatal("the deficit must block further admission")
	}
	clk.advance(4 * time.Second) // deficit -400 + 400 refill = 0: still blocked
	if g.AdmitN(ctx, "tnA", MeterFlowEvents, 1) {
		t.Fatal("the deficit is repaid at the configured rate")
	}
	clk.advance(time.Second)
	if !g.AdmitN(ctx, "tnA", MeterFlowEvents, 1) {
		t.Fatal("after repayment the tenant flows again")
	}
}

// TestPolicyLifecycle: overrides apply after the async fetch; a store outage
// degrades to the deployment defaults (still enforced); Invalidate picks up
// a provider change without waiting for the TTL.
func TestPolicyLifecycle(t *testing.T) {
	src := &memSource{policies: map[string]Policy{}}
	defaults := Policy{ResultsPerSec: 1000}
	g := NewGate(defaults, src).WithPolicyTTL(time.Hour)
	ctx := context.Background()

	// No override: the deployment default is the effective policy.
	if p := g.EffectivePolicy(ctx, "tnA"); p.ResultsPerSec != 1000 {
		t.Fatalf("default: %+v", p)
	}
	// The provider sets an override + invalidates (the PUT path).
	src.mu.Lock()
	src.policies["tnA"] = Policy{ResultsPerSec: 50}
	src.mu.Unlock()
	g.Invalidate("tnA")
	g.EffectivePolicy(ctx, "tnA") // schedules the refresh
	eventually(t, func() bool { return g.EffectivePolicy(ctx, "tnA").ResultsPerSec == 50 })

	// Unset override fields inherit the deployment defaults.
	if p := g.EffectivePolicy(ctx, "tnA"); p.BurstSeconds != 10 {
		t.Fatalf("merged burst default: %+v", p)
	}

	// A policy-store outage keeps the LAST KNOWN policy through TTL and
	// degrades to defaults on refresh — never an open gate panic, never a
	// blocked ingest path.
	src.mu.Lock()
	src.fail = true
	src.mu.Unlock()
	g.Invalidate("tnA")
	g.EffectivePolicy(ctx, "tnA")
	eventually(t, func() bool { return g.EffectivePolicy(ctx, "tnA").ResultsPerSec == 1000 })
}

// TestUnlimitedByDefault: with nothing configured the gate admits everything
// and rejects nothing — small deployments pay nothing for fairness.
func TestUnlimitedByDefault(t *testing.T) {
	g := NewGate(Policy{}, nil)
	ctx := context.Background()
	for range 10000 {
		if !g.AdmitN(ctx, "tnA", MeterResults, 1) {
			t.Fatal("unbounded deployments must never shed")
		}
	}
	for range 100 {
		rel, err := g.BeginQuery(ctx, "tnA")
		if err != nil {
			t.Fatal(err)
		}
		rel()
	}
	snap := g.SnapshotTenant(ctx, "tnA")
	if snap.Ingest[MeterResults].ShedUnits != 0 || snap.Queries.RejectedBudget != 0 {
		t.Fatalf("nothing may be shed when unbounded: %+v", snap)
	}
}
