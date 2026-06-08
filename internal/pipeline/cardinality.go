package pipeline

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// Cardinality caps (U-017): Result.Metrics is agent-supplied, so a single
// misbehaving (or hostile) agent could mint unbounded unique series and blow
// up every store downstream. Ingest now tracks ACTIVE series identities per
// (tenant, agent) and per tenant; a NEW identity past the cap is rejected
// (dropped + counted, per-series — known identities keep flowing), so one
// agent's explosion can never become another tenant's problem (the fairness
// stance, S-T7).

// Default caps: generous for real probes (a canary emits a handful of
// metrics), hard walls for an explosion.
const (
	DefaultMaxSeriesPerAgent  = 1000
	DefaultMaxSeriesPerTenant = 50000

	// Eviction (Sprint 15, SCALE-003): an identity idle past the TTL frees
	// its slot — agent/series churn no longer grows the limiter forever.
	// Cross-replica sharing is DELIBERATELY not implemented: per-replica
	// caps tolerate replicas×cap worst-case (documented trade-off) instead
	// of adding a stateful dependency to the ingest hot path.
	DefaultSeriesIdleTTL = time.Hour
	sweepInterval        = time.Minute
)

// CardinalityLimiter admits series identities under per-agent and per-tenant
// caps. It is safe for concurrent use.
type CardinalityLimiter struct {
	perAgent  int
	perTenant int
	idleTTL   time.Duration

	mu        sync.Mutex
	tenants   map[string]*tenantSeries
	dropped   uint64 // total rejected series (never silent)
	evicted   uint64 // identities freed by the idle sweep
	lastSweep time.Time
	now       func() time.Time
}

type tenantSeries struct {
	all     map[string]time.Time            // tenant-wide identities -> last seen
	byAgent map[string]map[string]time.Time // agent -> identity -> last seen
	dropped uint64
}

// NewCardinalityLimiter builds a limiter; non-positive caps use the defaults.
func NewCardinalityLimiter(perAgent, perTenant int) *CardinalityLimiter {
	if perAgent <= 0 {
		perAgent = DefaultMaxSeriesPerAgent
	}
	if perTenant <= 0 {
		perTenant = DefaultMaxSeriesPerTenant
	}
	return &CardinalityLimiter{
		perAgent: perAgent, perTenant: perTenant, idleTTL: DefaultSeriesIdleTTL,
		tenants: map[string]*tenantSeries{}, now: time.Now,
	}
}

// WithIdleTTL overrides the identity idle eviction window (tests; config).
func (l *CardinalityLimiter) WithIdleTTL(ttl time.Duration) *CardinalityLimiter {
	if ttl > 0 {
		l.idleTTL = ttl
	}
	return l
}

// sweepLocked frees identities idle past the TTL and removes empty agents and
// tenants — the memory bound (SCALE-003). Called under mu, at most once per
// sweepInterval, from the Filter hot path (amortized; no background goroutine
// to leak).
func (l *CardinalityLimiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < sweepInterval {
		return
	}
	l.lastSweep = now
	cutoff := now.Add(-l.idleTTL)
	for tenant, ts := range l.tenants {
		for agent, ids := range ts.byAgent {
			for id, seen := range ids {
				if seen.Before(cutoff) {
					delete(ids, id)
					delete(ts.all, id)
					l.evicted++
				}
			}
			if len(ids) == 0 {
				delete(ts.byAgent, agent)
			}
		}
		if len(ts.all) == 0 && ts.dropped == 0 {
			delete(l.tenants, tenant)
		}
	}
}

// seriesIdentity is the cardinality key: metric name + every label pair.
func seriesIdentity(s tsdb.Series) string {
	keys := make([]string, 0, len(s.Labels))
	for k := range s.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(s.Metric)
	for _, k := range keys {
		b.WriteByte(0)
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(s.Labels[k])
	}
	return b.String()
}

// Filter returns the admitted subset of series for (tenant, agent) and the
// number rejected by the caps. Known identities always pass (steady-state
// telemetry keeps flowing at the cap); only NEW identities are gated.
func (l *CardinalityLimiter) Filter(tenant, agent string, series []tsdb.Series) ([]tsdb.Series, int) {
	if l == nil {
		return series, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweepLocked(now)

	ts := l.tenants[tenant]
	if ts == nil {
		ts = &tenantSeries{all: map[string]time.Time{}, byAgent: map[string]map[string]time.Time{}}
		l.tenants[tenant] = ts
	}
	ag := ts.byAgent[agent]
	if ag == nil {
		ag = map[string]time.Time{}
		ts.byAgent[agent] = ag
	}

	admitted := series[:0]
	droppedHere := 0
	for _, s := range series {
		id := seriesIdentity(s)
		if _, known := ag[id]; known {
			ag[id] = now // refresh last-seen: live series never evict
			ts.all[id] = now
			admitted = append(admitted, s)
			continue
		}
		if len(ag) >= l.perAgent || len(ts.all) >= l.perTenant {
			droppedHere++
			continue
		}
		ag[id] = now
		ts.all[id] = now
		admitted = append(admitted, s)
	}
	if droppedHere > 0 {
		l.dropped += uint64(droppedHere)
		ts.dropped += uint64(droppedHere)
	}
	return admitted, droppedHere
}

// CardinalityStats reports the rejection counters.
type CardinalityStats struct {
	Dropped       uint64
	Evicted       uint64 // identities freed by the idle sweep (SCALE-003)
	ActiveSeries  int    // live identities across all tenants (the memory bound)
	TenantDropped map[string]uint64
}

// Stats snapshots the counters (per-tenant drops included, for fairness
// visibility).
func (l *CardinalityLimiter) Stats() CardinalityStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := CardinalityStats{Dropped: l.dropped, Evicted: l.evicted, TenantDropped: map[string]uint64{}}
	for t, ts := range l.tenants {
		out.ActiveSeries += len(ts.all)
		if ts.dropped > 0 {
			out.TenantDropped[t] = ts.dropped
		}
	}
	return out
}
