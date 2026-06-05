// Package fairness is the core per-tenant fairness layer (S-T7, F57): in a
// pooled deployment one tenant must not be able to degrade the others.
// Enforcement lives in CORE by ratified decision — it protects the pooled
// platform itself — while the provider-console fairness views ride ee/.
//
// Three mechanisms, all per tenant and all observable:
//
//   - Ingest rate bounds: token buckets per (tenant, meter) on the result and
//     flow consumers. Over-rate traffic is SHED with accounting — bounded
//     admission to the expensive section (decode→store) is what keeps one
//     tenant's burst from stalling the shared pipeline (backpressure
//     isolation). Because the gate wraps the CONSUMER, it behaves identically
//     under Kafka and the lightweight bus modes (the S-T7 watch-out).
//   - Query-cost guards: per-tenant in-flight concurrency + a per-minute
//     query budget on the S23 query surfaces (AI ask, MCP, PromQL proxy).
//     Over-budget callers get 429, never a slow platform.
//   - Accounting: per-tenant admitted/shed/rejected counters, exposed on
//     /v1/fairness (the tenant debugging its own disputes), the provider
//     console (ee), and as TSDB series (Grafana-federable).
//
// The fail-open doctrine: an UNSET limit (zero) means unlimited — small and
// single-tenant deployments enforce nothing unless configured. A policy-store
// outage degrades to the deployment defaults (availability over precision; a
// down Postgres must not stall ingest). Shedding is never silent: every shed
// unit is counted, surfaced, and attributable. Cost guards bound CONCURRENCY
// and RATE, never total volume — a legitimately-busy tenant under its
// ceiling is never starved.
package fairness

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Meter names bounded by the ingest gate — the S-T3 usage vocabulary, so
// metering, quotas, and fairness agree about what a unit is.
const (
	MeterResults    = "results_ingested" // result messages admitted to the pipeline
	MeterFlowEvents = "flow_events"      // flow records admitted to the flow store
	MeterBytes      = "ingest_bytes"     // result payload bytes admitted
	meterQueries    = "queries"          // query-budget bucket (internal)
)

// Policy is the per-tenant fairness contract (the S-T7 "quotas / limits /
// weights"). The zero value of any field means UNLIMITED / deployment
// default — fairness is opt-in per bound.
type Policy struct {
	ResultsPerSec     float64 `json:"results_per_sec,omitempty"`
	FlowEventsPerSec  float64 `json:"flow_events_per_sec,omitempty"`
	IngestBytesPerSec float64 `json:"ingest_bytes_per_sec,omitempty"`
	// BurstSeconds sizes every bucket: capacity = rate × BurstSeconds
	// (default 10 — a tenant may burst ten seconds of its rate).
	BurstSeconds float64 `json:"burst_seconds,omitempty"`
	// QueryConcurrency caps a tenant's in-flight queries; QueriesPerMin
	// budgets its query rate. Both 0 = unlimited.
	QueryConcurrency int     `json:"query_concurrency,omitempty"`
	QueriesPerMin    float64 `json:"queries_per_min,omitempty"`
	// Weight is recorded for operators (relative share vocabulary for
	// fairness disputes and future weighted draining); it does not gate.
	Weight int `json:"weight,omitempty"`
}

// merged returns p with unset fields filled from the deployment defaults.
func (p Policy) merged(def Policy) Policy {
	out := p
	if out.ResultsPerSec == 0 {
		out.ResultsPerSec = def.ResultsPerSec
	}
	if out.FlowEventsPerSec == 0 {
		out.FlowEventsPerSec = def.FlowEventsPerSec
	}
	if out.IngestBytesPerSec == 0 {
		out.IngestBytesPerSec = def.IngestBytesPerSec
	}
	if out.BurstSeconds == 0 {
		out.BurstSeconds = def.BurstSeconds
	}
	if out.QueryConcurrency == 0 {
		out.QueryConcurrency = def.QueryConcurrency
	}
	if out.QueriesPerMin == 0 {
		out.QueriesPerMin = def.QueriesPerMin
	}
	if out.Weight == 0 {
		out.Weight = def.Weight
	}
	if out.BurstSeconds <= 0 {
		out.BurstSeconds = 10
	}
	return out
}

func (p Policy) rateFor(meter string) float64 {
	switch meter {
	case MeterResults:
		return p.ResultsPerSec
	case MeterFlowEvents:
		return p.FlowEventsPerSec
	case MeterBytes:
		return p.IngestBytesPerSec
	case meterQueries:
		return p.QueriesPerMin / 60
	}
	return 0 // unknown meters are unbounded (and unmetered)
}

// PolicySource resolves a tenant's stored policy override. ok=false means no
// override (deployment defaults apply). Implementations must be safe for
// concurrent use. A nil source = defaults for everyone.
type PolicySource interface {
	PolicyFor(ctx context.Context, tenantID string) (Policy, bool, error)
}

// Query-guard rejections (transport maps both to 429 rate_limited).
var (
	// ErrQueryConcurrency: the tenant's in-flight query cap is reached.
	ErrQueryConcurrency = errors.New("fairness: tenant query concurrency limit reached")
	// ErrQueryBudget: the tenant's per-minute query budget is exhausted.
	ErrQueryBudget = errors.New("fairness: tenant query budget exhausted")
)

// Counters is one tenant's accounting for one meter. Calls are admission
// decisions; units are what the calls carried (1 result, N flow rows, M
// bytes). Shed units are the fairness story a tenant can be shown.
type Counters struct {
	AdmittedCalls int64 `json:"admitted_calls"`
	AdmittedUnits int64 `json:"admitted_units"`
	ShedCalls     int64 `json:"shed_calls"`
	ShedUnits     int64 `json:"shed_units"`
}

// QueryCounters is one tenant's query-guard accounting.
type QueryCounters struct {
	Allowed             int64 `json:"allowed"`
	RejectedConcurrency int64 `json:"rejected_concurrency"`
	RejectedBudget      int64 `json:"rejected_budget"`
	InFlight            int64 `json:"in_flight"`
}

// Snapshot is a tenant's full fairness accounting + its effective policy.
type Snapshot struct {
	TenantID string              `json:"tenant_id"`
	Policy   Policy              `json:"policy"`
	Ingest   map[string]Counters `json:"ingest"`
	Queries  QueryCounters       `json:"queries"`
}

// bucket is a token bucket that may run a deficit: a call larger than the
// remaining tokens is admitted while tokens > 0 and drives the balance
// negative, which the refill claws back. That bounds the LONG-RUN rate at
// the limit while never permanently starving batches larger than the burst
// capacity (the "falsely starve a legitimately-busy tenant" watch-out).
type bucket struct {
	tokens float64
	last   time.Time
}

type tenantState struct {
	buckets map[string]*bucket // meter -> bucket
	ingest  map[string]*Counters
	queries QueryCounters

	policy         Policy
	policyFetched  time.Time
	policyKnown    bool
	policyFetching bool
}

// Gate is the fairness enforcement point. One Gate serves the whole process
// (consumers, query handlers, surfaces) so accounting is coherent.
type Gate struct {
	defaults  Policy
	source    PolicySource
	policyTTL time.Duration

	mu      sync.Mutex
	tenants map[string]*tenantState

	now func() time.Time
}

// NewGate builds a Gate with deployment defaults and an optional stored
// policy source (nil = defaults only).
func NewGate(defaults Policy, source PolicySource) *Gate {
	return &Gate{
		defaults:  defaults.merged(Policy{}),
		source:    source,
		policyTTL: time.Minute,
		tenants:   map[string]*tenantState{},
		now:       time.Now,
	}
}

// WithPolicyTTL overrides the policy cache TTL (tests).
func (g *Gate) WithPolicyTTL(d time.Duration) *Gate {
	if d > 0 {
		g.policyTTL = d
	}
	return g
}

// WithNow injects a clock (tests).
func (g *Gate) WithNow(now func() time.Time) *Gate {
	if now != nil {
		g.now = now
	}
	return g
}

func (g *Gate) state(tenantID string) *tenantState {
	st, ok := g.tenants[tenantID]
	if !ok {
		st = &tenantState{buckets: map[string]*bucket{}, ingest: map[string]*Counters{}}
		g.tenants[tenantID] = st
	}
	return st
}

// policyFor resolves the tenant's effective policy under g.mu. The stored
// override is fetched ASYNCHRONOUSLY: admission never blocks on Postgres —
// a slow policy store would otherwise be a noisy neighbor to every tenant.
// Until the first fetch lands (and whenever the source errors) the
// deployment defaults apply — availability first, bounds still enforced.
func (g *Gate) policyFor(_ context.Context, st *tenantState, tenantID string) Policy {
	if st.policyKnown && g.now().Sub(st.policyFetched) < g.policyTTL {
		return st.policy
	}
	if !st.policyKnown {
		// First sight of this tenant: enforce defaults immediately.
		st.policy = g.defaults
		st.policyKnown = true
		st.policyFetched = g.now()
	}
	if g.source != nil && !st.policyFetching {
		st.policyFetching = true
		go g.refresh(tenantID)
	} else if g.source == nil {
		st.policyFetched = g.now()
	}
	return st.policy
}

// refresh fetches the stored override off the hot path and installs it.
func (g *Gate) refresh(tenantID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	eff := g.defaults
	if p, ok, err := g.source.PolicyFor(ctx, tenantID); err == nil && ok {
		eff = p.merged(g.defaults)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.state(tenantID)
	st.policy = eff
	st.policyKnown = true
	st.policyFetched = g.now()
	st.policyFetching = false
}

// EffectivePolicy is the tenant's policy as enforced right now (defaults +
// override merge) — the /v1/fairness self-view.
func (g *Gate) EffectivePolicy(ctx context.Context, tenantID string) Policy {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.policyFor(ctx, g.state(tenantID), tenantID)
}

// Invalidate drops a tenant's cached policy (the provider just changed it).
func (g *Gate) Invalidate(tenantID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if st, ok := g.tenants[tenantID]; ok {
		st.policyKnown = false
	}
}

// take refills and charges a bucket; admission while tokens > 0 (deficit
// semantics, see bucket). rate<=0 = unlimited.
func (g *Gate) take(st *tenantState, meter string, rate, capacity float64, n int64) bool {
	if rate <= 0 {
		return true
	}
	b, ok := st.buckets[meter]
	now := g.now()
	if !ok {
		b = &bucket{tokens: capacity, last: now}
		st.buckets[meter] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > capacity {
		b.tokens = capacity
	}
	b.last = now
	if b.tokens <= 0 {
		return false
	}
	b.tokens -= float64(n)
	return true
}

// AdmitN decides whether n units of meter are within the tenant's bounds and
// charges them. Shed work is counted, never silent. The call is O(1) and
// lock-cheap — it sits on the hot ingest path.
func (g *Gate) AdmitN(ctx context.Context, tenantID, meter string, n int64) bool {
	if tenantID == "" {
		return true // unattributable messages are the pipeline's problem, not fairness's
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.state(tenantID)
	pol := g.policyFor(ctx, st, tenantID)
	rate := pol.rateFor(meter)
	c, ok := st.ingest[meter]
	if !ok {
		c = &Counters{}
		st.ingest[meter] = c
	}
	if g.take(st, meter, rate, rate*pol.BurstSeconds, n) {
		c.AdmittedCalls++
		c.AdmittedUnits += n
		return true
	}
	c.ShedCalls++
	c.ShedUnits += n
	return false
}

// BeginQuery admits one query under the tenant's concurrency + budget
// guards. On success the returned release MUST be called when the query
// finishes. On rejection it returns ErrQueryConcurrency or ErrQueryBudget.
func (g *Gate) BeginQuery(ctx context.Context, tenantID string) (release func(), err error) {
	if tenantID == "" {
		return func() {}, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.state(tenantID)
	pol := g.policyFor(ctx, st, tenantID)
	if pol.QueryConcurrency > 0 && st.queries.InFlight >= int64(pol.QueryConcurrency) {
		st.queries.RejectedConcurrency++
		return nil, ErrQueryConcurrency
	}
	// The query bucket's capacity is one full minute of budget: a tenant may
	// issue its whole per-minute allowance back-to-back, then refills at
	// QueriesPerMin/60 per second.
	rate := pol.rateFor(meterQueries)
	if !g.take(st, meterQueries, rate, rate*60, 1) {
		st.queries.RejectedBudget++
		return nil, ErrQueryBudget
	}
	st.queries.Allowed++
	st.queries.InFlight++
	done := false
	return func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if !done {
			done = true
			st.queries.InFlight--
		}
	}, nil
}

// SnapshotTenant returns one tenant's accounting + effective policy.
func (g *Gate) SnapshotTenant(ctx context.Context, tenantID string) Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.state(tenantID)
	return snapshotLocked(tenantID, st, g.policyFor(ctx, st, tenantID))
}

// SnapshotAll returns every tenant the gate has seen, sorted by tenant ID —
// the provider-console fairness view (ee reads it through this core call).
func (g *Gate) SnapshotAll() []Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]Snapshot, 0, len(g.tenants))
	for id, st := range g.tenants {
		out = append(out, snapshotLocked(id, st, st.policy))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	return out
}

func snapshotLocked(tenantID string, st *tenantState, pol Policy) Snapshot {
	s := Snapshot{TenantID: tenantID, Policy: pol, Ingest: map[string]Counters{}, Queries: st.queries}
	for m, c := range st.ingest {
		s.Ingest[m] = *c
	}
	return s
}

// ParseRate parses an integer-ish env value into a float rate (config glue).
func ParseRate(v string) float64 {
	if v == "" {
		return 0
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 {
		return 0
	}
	return f
}
