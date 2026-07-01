// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
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

	// SCALE-007: per-series label caps. The series-count cap alone does not stop
	// ONE admitted identity from carrying thousands of labels or megabyte label
	// values (the identity key is built from agent-supplied labels). These caps
	// match the OTLP plane's stance: a series with too many labels is dropped
	// (counted), and an over-long label value is truncated before it becomes
	// part of the identity. Native sources are already schema-bounded; this
	// guards the agent-supplied Result.Metrics path.
	maxLabelsPerSeries = 32
	maxLabelValueLen   = 256
	labelHashPrefixLen = 32

	// SPINE-006: stripe tenant state so high-cardinality ingest for different
	// tenants does not serialize on one process-wide mutex. One tenant still maps
	// to exactly one shard, preserving per-tenant/per-agent cap semantics.
	cardinalityShards = 32
)

// CardinalityLimiter admits series identities under per-agent and per-tenant
// caps. It is safe for concurrent use.
type CardinalityLimiter struct {
	perAgent  int
	perTenant int
	idleTTL   time.Duration

	shards [cardinalityShards]cardinalityShard

	dropped   atomic.Uint64 // total rejected series (never silent)
	truncated atomic.Uint64 // total label values normalized with a hash marker
	evicted   atomic.Uint64 // identities freed by the idle sweep
	now       func() time.Time
}

type cardinalityShard struct {
	mu        sync.Mutex
	tenants   map[string]*tenantSeries
	lastSweep time.Time
}

type tenantSeries struct {
	all       map[string]time.Time            // tenant-wide identities -> last seen
	byAgent   map[string]map[string]time.Time // agent -> identity -> last seen
	dropped   uint64
	truncated uint64
}

// NewCardinalityLimiter builds a limiter; non-positive caps use the defaults.
func NewCardinalityLimiter(perAgent, perTenant int) *CardinalityLimiter {
	if perAgent <= 0 {
		perAgent = DefaultMaxSeriesPerAgent
	}
	if perTenant <= 0 {
		perTenant = DefaultMaxSeriesPerTenant
	}
	l := &CardinalityLimiter{perAgent: perAgent, perTenant: perTenant, idleTTL: DefaultSeriesIdleTTL, now: time.Now}
	for i := range l.shards {
		l.shards[i].tenants = map[string]*tenantSeries{}
	}
	return l
}

// WithIdleTTL overrides the identity idle eviction window (tests; config).
func (l *CardinalityLimiter) WithIdleTTL(ttl time.Duration) *CardinalityLimiter {
	if ttl > 0 {
		l.idleTTL = ttl
	}
	return l
}

// shardFor maps a tenant to its cardinality state stripe (FNV-1a, mirroring the
// fairness gate's tenant hash). A tenant is always on the same shard, so its
// state never spans locks.
func (l *CardinalityLimiter) shardFor(tenantID string) *cardinalityShard {
	var h uint32 = 2166136261
	for i := 0; i < len(tenantID); i++ {
		h ^= uint32(tenantID[i])
		h *= 16777619
	}
	return &l.shards[h%cardinalityShards]
}

// sweepLocked frees identities idle past the TTL and removes empty agents and
// tenants — the memory bound (SCALE-003). Called under the tenant shard lock, at
// most once per sweepInterval per shard, from the Filter hot path (amortized; no
// background goroutine to leak).
func (l *CardinalityLimiter) sweepLocked(sh *cardinalityShard, now time.Time) {
	if now.Sub(sh.lastSweep) < sweepInterval {
		return
	}
	sh.lastSweep = now
	cutoff := now.Add(-l.idleTTL)
	for tenant, ts := range sh.tenants {
		for agent, ids := range ts.byAgent {
			for id, seen := range ids {
				if seen.Before(cutoff) {
					delete(ids, id)
					delete(ts.all, id)
					l.evicted.Add(1)
				}
			}
			if len(ids) == 0 {
				delete(ts.byAgent, agent)
			}
		}
		if len(ts.all) == 0 && ts.dropped == 0 && ts.truncated == 0 {
			delete(sh.tenants, tenant)
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

func boundedLabelValue(v string) (string, bool) {
	if len(v) <= maxLabelValueLen {
		return v, false
	}
	sum := hex.EncodeToString(crypto.Hash([]byte(v)))[:labelHashPrefixLen]
	return "truncated:sha256:" + sum + ":len:" + strconv.Itoa(len(v)), true
}

// CardinalityFilterStats is per-call accounting for integrity ledgers.
type CardinalityFilterStats struct {
	Dropped        int
	LabelTruncated int
}

// Filter returns the admitted subset of series for (tenant, agent) and the
// number rejected by the caps. Known identities always pass (steady-state
// telemetry keeps flowing at the cap); only NEW identities are gated.
func (l *CardinalityLimiter) Filter(tenant, agent string, series []tsdb.Series) ([]tsdb.Series, int) {
	admitted, st := l.FilterDetailed(tenant, agent, series)
	return admitted, st.Dropped
}

// FilterDetailed is Filter plus per-call normalization/drop accounting for
// pipeline integrity ledgers.
func (l *CardinalityLimiter) FilterDetailed(tenant, agent string, series []tsdb.Series) ([]tsdb.Series, CardinalityFilterStats) {
	if l == nil {
		return series, CardinalityFilterStats{}
	}
	now := l.now()
	sh := l.shardFor(tenant)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	l.sweepLocked(sh, now)

	ts := sh.tenants[tenant]
	if ts == nil {
		ts = &tenantSeries{all: map[string]time.Time{}, byAgent: map[string]map[string]time.Time{}}
		sh.tenants[tenant] = ts
	}
	ag := ts.byAgent[agent]
	if ag == nil {
		ag = map[string]time.Time{}
		ts.byAgent[agent] = ag
	}

	admitted := series[:0]
	droppedHere := 0
	truncatedHere := 0
	for _, s := range series {
		// SCALE-007: a series with too many labels is rejected outright (a
		// label explosion is as damaging as a series explosion); over-long
		// label VALUES are replaced with a deterministic hash marker before
		// they enter the identity key. The marker is bounded, non-conflating,
		// and visible in integrity counters instead of silently aliasing two
		// different values that share the same prefix.
		if len(s.Labels) > maxLabelsPerSeries {
			droppedHere++
			continue
		}
		for k, v := range s.Labels {
			if bounded, ok := boundedLabelValue(v); ok {
				s.Labels[k] = bounded
				truncatedHere++
			}
		}
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
		l.dropped.Add(uint64(droppedHere))
		ts.dropped += uint64(droppedHere)
	}
	if truncatedHere > 0 {
		l.truncated.Add(uint64(truncatedHere))
		ts.truncated += uint64(truncatedHere)
	}
	return admitted, CardinalityFilterStats{Dropped: droppedHere, LabelTruncated: truncatedHere}
}

// CardinalityStats reports the rejection counters.
type CardinalityStats struct {
	Dropped            uint64
	LabelTruncated     uint64 // label values normalized with a hash marker
	Evicted            uint64 // identities freed by the idle sweep (SCALE-003)
	ActiveSeries       int    // live identities across all tenants (the memory bound)
	TenantActiveSeries map[string]int
	TenantDropped      map[string]uint64
	TenantTruncated    map[string]uint64
}

// Stats snapshots the counters (per-tenant drops included, for fairness
// visibility).
func (l *CardinalityLimiter) Stats() CardinalityStats {
	out := CardinalityStats{
		Dropped:            l.dropped.Load(),
		LabelTruncated:     l.truncated.Load(),
		Evicted:            l.evicted.Load(),
		TenantActiveSeries: map[string]int{},
		TenantDropped:      map[string]uint64{},
		TenantTruncated:    map[string]uint64{},
	}
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		for t, ts := range sh.tenants {
			active := len(ts.all)
			out.ActiveSeries += active
			if active > 0 {
				out.TenantActiveSeries[t] = active
			}
			if ts.dropped > 0 {
				out.TenantDropped[t] = ts.dropped
			}
			if ts.truncated > 0 {
				out.TenantTruncated[t] = ts.truncated
			}
		}
		sh.mu.Unlock()
	}
	return out
}
