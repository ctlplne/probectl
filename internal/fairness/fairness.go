// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
// Defaults doctrine: the deployment ships SANE per-tenant ingest bounds on
// every plane, enabled by default (not opt-in). A zero or unset policy field
// means "use the deployment default" — which is itself bounded — so to change a
// bound you set a POSITIVE value; there is no negative override for any bound
// (explicit 0 in deployment config is the only unlimited posture). A policy-store
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
	"sync/atomic"
	"time"
)

// Meter names bounded by the ingest gate — the S-T3 usage vocabulary, so
// metering, quotas, and fairness agree about what a unit is.
const (
	MeterResults       = "results_ingested" // result messages admitted to the pipeline
	MeterFlowEvents    = "flow_events"      // flow records admitted to the flow store
	MeterBytes         = "ingest_bytes"     // result payload bytes admitted
	MeterDeviceMetrics = "device_metrics"   // device samples admitted (SCALE-005)
	MeterOTLPSeries    = "otlp_series"      // OTLP metric/trace/log series admitted (SCALE-003)
	meterQueries       = "queries"          // query-budget bucket (internal)
)

// Policy is the per-tenant fairness contract (the S-T7 "quotas / limits /
// weights"). The zero value of any field means "inherit" — merged() fills it
// from the deployment default, so fairness stays bounded by default.
// DefaultPolicy is the bounded-by-default deployment policy (SCALE-004):
// generous for real fleets, a hard wall for a runaway tenant. Override per
// deployment via PROBECTL_FAIRNESS_* (the env loader REJECTS negative values
// at boot — config.go float()); the engine-level rate<=0 = unlimited branch
// in take() is reachable only via an explicit per-tenant override, never an
// env value.
func DefaultPolicy() Policy {
	return Policy{
		ResultsPerSec:       1000,
		FlowEventsPerSec:    10000,
		IngestBytesPerSec:   2 << 20, // 2 MiB/s
		DeviceMetricsPerSec: 2000,
		OTLPSeriesPerSec:    5000,
		BurstSeconds:        10,
	}
}

type Policy struct {
	ResultsPerSec     float64 `json:"results_per_sec,omitempty"`
	FlowEventsPerSec  float64 `json:"flow_events_per_sec,omitempty"`
	IngestBytesPerSec float64 `json:"ingest_bytes_per_sec,omitempty"`
	// DeviceMetricsPerSec bounds the SNMP/gNMI device plane (SCALE-005).
	DeviceMetricsPerSec float64 `json:"device_metrics_per_sec,omitempty"`
	// OTLPSeriesPerSec bounds externally-ingested OTLP series (metrics, trace
	// spans, log records) per tenant (SCALE-003) — the OTLP planes had no
	// fairness gate, unlike the native planes.
	OTLPSeriesPerSec float64 `json:"otlp_series_per_sec,omitempty"`
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
	if out.DeviceMetricsPerSec == 0 {
		out.DeviceMetricsPerSec = def.DeviceMetricsPerSec
	}
	if out.OTLPSeriesPerSec == 0 {
		out.OTLPSeriesPerSec = def.OTLPSeriesPerSec
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
	case MeterDeviceMetrics:
		return p.DeviceMetricsPerSec
	case MeterOTLPSeries:
		return p.OTLPSeriesPerSec
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

	// lastSeen is the last time this tenant touched the gate (an admit or a
	// query). The amortized idle sweep (SCALE-002 / RED-003b) evicts state idle
	// past the TTL so per-tenant churn — short-lived tenants, offboarded
	// tenants, transient ids — no longer grows the gate's map forever (an
	// unbounded-allocation memory DoS). Live tenants refresh it on every call,
	// so a busy tenant never evicts.
	lastSeen time.Time
}

// gateShards stripes the Gate's per-tenant state so admissions for DIFFERENT
// tenants don't serialize on one global mutex (SCALE-001 — the admit hot path
// took a single process-wide lock, so under high tenant fan-in every tenant
// queued behind every other). A tenant always maps to ONE shard via a stable
// hash, so its state stays under a single lock: per-tenant admit semantics
// (deficit token buckets, counters, the policy cache) are UNCHANGED; only the
// cross-tenant contention is removed.
const gateShards = 32

// Idle eviction (SCALE-002 / RED-003b), mirroring pipeline.CardinalityLimiter:
// the gate's per-tenant state is swept on the admit hot path, at most once per
// gateSweepInterval per shard, and any tenant idle past idleTTL is deleted.
// This bounds the gate's memory under tenant churn (the unbounded-map DoS)
// without a background goroutine to leak — the sweep is amortized into the
// admission call that already holds the shard lock.
const (
	// DefaultGateIdleTTL is how long a tenant's fairness state survives with no
	// admits/queries before the idle sweep reclaims it. Generous: a tenant
	// silent for a full day is treated as gone; the next message re-creates its
	// state (and re-enforces defaults immediately) at negligible cost.
	DefaultGateIdleTTL = 24 * time.Hour
	// gateSweepInterval bounds how often a shard runs the O(tenants-in-shard)
	// sweep, so the hot path pays for it at most once per minute per shard.
	gateSweepInterval = time.Minute
)

type gateShard struct {
	mu        sync.Mutex
	tenants   map[string]*tenantState
	lastSweep time.Time
}

// Gate is the fairness enforcement point. One Gate serves the whole process
// (consumers, query handlers, surfaces) so accounting is coherent.
type Gate struct {
	defaults  Policy
	source    PolicySource
	policyTTL time.Duration
	idleTTL   time.Duration // SCALE-002: per-tenant idle eviction window

	shards [gateShards]gateShard

	evicted atomic.Uint64 // tenants reclaimed by the idle sweep (observability)

	now func() time.Time
}

// NewGate builds a Gate with deployment defaults and an optional stored
// policy source (nil = defaults only).
func NewGate(defaults Policy, source PolicySource) *Gate {
	g := &Gate{
		defaults:  defaults.merged(Policy{}),
		source:    source,
		policyTTL: time.Minute,
		idleTTL:   DefaultGateIdleTTL,
		now:       time.Now,
	}
	for i := range g.shards {
		g.shards[i].tenants = map[string]*tenantState{}
	}
	return g
}

// WithIdleTTL overrides the per-tenant idle eviction window (SCALE-002; config
// via PROBECTL_FAIRNESS_TENANT_IDLE_TTL). Non-positive keeps the default.
func (g *Gate) WithIdleTTL(d time.Duration) *Gate {
	if d > 0 {
		g.idleTTL = d
	}
	return g
}

// shardFor maps a tenant to its state stripe (FNV-1a, the bus key hash family).
// A tenant is always on the same shard, so its state never spans locks.
func (g *Gate) shardFor(tenantID string) *gateShard {
	var h uint32 = 2166136261
	for i := 0; i < len(tenantID); i++ {
		h ^= uint32(tenantID[i])
		h *= 16777619
	}
	return &g.shards[h%gateShards]
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

// state returns (creating if needed) the tenant's state within its shard. The
// caller MUST hold sh.mu. A freshly created state is stamped lastSeen=now so a
// tenant just brought into the map (by an admit, a query, or a read surface) is
// never immediately evicted by the idle sweep — only genuine idleness past
// idleTTL reclaims it (SCALE-002).
func (g *Gate) state(sh *gateShard, tenantID string) *tenantState {
	st, ok := sh.tenants[tenantID]
	if !ok {
		st = &tenantState{buckets: map[string]*bucket{}, ingest: map[string]*Counters{}, lastSeen: g.now()}
		sh.tenants[tenantID] = st
	}
	return st
}

// sweepShardLocked evicts tenants in this shard idle past idleTTL, at most once
// per gateSweepInterval (SCALE-002 / RED-003b — the CardinalityLimiter.sweepLocked
// pattern). The caller MUST hold sh.mu. It is amortized onto the admission call
// that already holds the lock, so it adds no goroutine and bounds the map under
// tenant churn. Tenants currently in a fetch (policyFetching) or holding
// in-flight queries are kept — evicting them would race the async refresh or
// drop a live release accounting.
func (g *Gate) sweepShardLocked(sh *gateShard, now time.Time) {
	if now.Sub(sh.lastSweep) < gateSweepInterval {
		return
	}
	sh.lastSweep = now
	cutoff := now.Add(-g.idleTTL)
	for id, st := range sh.tenants {
		if st.policyFetching || st.queries.InFlight > 0 {
			continue
		}
		if st.lastSeen.Before(cutoff) {
			delete(sh.tenants, id)
			g.evicted.Add(1)
		}
	}
}

// Evicted reports how many tenants the idle sweep has reclaimed (SCALE-002
// observability — exposed so the unbounded-map fix is provable in production,
// not just in tests).
func (g *Gate) Evicted() uint64 { return g.evicted.Load() }

// policyFor resolves the tenant's effective policy under the tenant's shard
// lock (held by the caller). The stored
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
	sh := g.shardFor(tenantID)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	st := g.state(sh, tenantID)
	st.policy = eff
	st.policyKnown = true
	st.policyFetched = g.now()
	st.policyFetching = false
}

// EffectivePolicy is the tenant's policy as enforced right now (defaults +
// override merge) — the /v1/fairness self-view.
func (g *Gate) EffectivePolicy(ctx context.Context, tenantID string) Policy {
	sh := g.shardFor(tenantID)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return g.policyFor(ctx, g.state(sh, tenantID), tenantID)
}

// Invalidate drops a tenant's cached policy (the provider just changed it).
func (g *Gate) Invalidate(tenantID string) {
	sh := g.shardFor(tenantID)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if st, ok := sh.tenants[tenantID]; ok {
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
	sh := g.shardFor(tenantID)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	now := g.now()
	g.sweepShardLocked(sh, now) // SCALE-002: amortized idle eviction
	st := g.state(sh, tenantID)
	st.lastSeen = now // live tenants never evict
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
	sh := g.shardFor(tenantID)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	now := g.now()
	g.sweepShardLocked(sh, now) // SCALE-002: amortized idle eviction
	st := g.state(sh, tenantID)
	st.lastSeen = now // live tenants (and any with in-flight queries) never evict
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
		sh.mu.Lock()
		defer sh.mu.Unlock()
		if !done {
			done = true
			st.queries.InFlight--
		}
	}, nil
}

// SnapshotTenant returns one tenant's accounting + effective policy.
func (g *Gate) SnapshotTenant(ctx context.Context, tenantID string) Snapshot {
	sh := g.shardFor(tenantID)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	st := g.state(sh, tenantID)
	return snapshotLocked(tenantID, st, g.policyFor(ctx, st, tenantID))
}

// SnapshotAll returns every tenant the gate has seen, sorted by tenant ID —
// the provider-console fairness view (ee reads it through this core call). It
// locks each shard in turn (one at a time, no deadlock); it's a read surface,
// not on the hot path, so a per-shard-consistent view is sufficient.
func (g *Gate) SnapshotAll() []Snapshot {
	var out []Snapshot
	for i := range g.shards {
		sh := &g.shards[i]
		sh.mu.Lock()
		for id, st := range sh.tenants {
			out = append(out, snapshotLocked(id, st, st.policy))
		}
		sh.mu.Unlock()
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
