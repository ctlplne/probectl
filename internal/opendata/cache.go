// SPDX-License-Identifier: LicenseRef-probectl-TBD

package opendata

import (
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/metrics"
)

// DefaultCacheMaxEntries is the process-wide safety wall for the shared
// enrichment cache. It is deliberately finite: open-data enrichment is shared
// across tenants, so distinct-IP floods must evict instead of growing memory
// without bound.
const DefaultCacheMaxEntries = 65536

// cache is a small TTL cache of enrichment results, keyed by IP. It exists to
// shield rate-limited / slow upstreams: an IP looked up twice within the TTL is
// served from memory (S15 watch-out — cache aggressively).
type cache struct {
	mu  sync.Mutex
	ttl time.Duration
	max int
	m   map[string]cacheEntry
	now func() time.Time

	hits, misses, evictions, expired uint64
	metrics                          cacheMetrics
}

type cacheEntry struct {
	e    Enrichment
	exp  time.Time
	last time.Time
}

type cacheMetrics struct {
	hits, misses, evictions, expired *metrics.Counter
}

type CacheStats struct {
	Entries, MaxEntries              int
	ApproxBytes                      int64
	Hits, Misses, Evictions, Expired uint64
}

func newCache(ttl time.Duration) *cache {
	return &cache{ttl: ttl, max: DefaultCacheMaxEntries, m: make(map[string]cacheEntry), now: time.Now}
}

func (c *cache) get(key string) (Enrichment, bool) {
	if c.ttl <= 0 || c.max <= 0 {
		return Enrichment{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	ent, ok := c.m[key]
	if !ok {
		c.recordMissLocked()
		return Enrichment{}, false
	}
	if !now.Before(ent.exp) {
		delete(c.m, key)
		c.recordExpiredLocked(1)
		c.recordMissLocked()
		return Enrichment{}, false
	}
	ent.last = now
	c.m[key] = ent
	c.recordHitLocked()
	return ent.e, true
}

func (c *cache) put(key string, e Enrichment) {
	if c.ttl <= 0 || c.max <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if _, exists := c.m[key]; !exists && len(c.m) >= c.max {
		c.evictExpiredLocked(now)
	}
	if _, exists := c.m[key]; !exists && len(c.m) >= c.max {
		c.evictOldestLocked()
	}
	c.m[key] = cacheEntry{e: e, exp: now.Add(c.ttl), last: now}
}

func (c *cache) setTTL(ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttl = ttl
	if ttl <= 0 {
		c.m = make(map[string]cacheEntry)
	}
}

func (c *cache) setMax(limit int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.max = limit
	if limit <= 0 {
		c.m = make(map[string]cacheEntry)
		return
	}
	now := c.now()
	c.evictExpiredLocked(now)
	for len(c.m) > limit {
		c.evictOldestLocked()
	}
}

func (c *cache) stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	var approx int64
	for key, ent := range c.m {
		approx += cacheEntryApproxBytes(key, ent.e)
	}
	return CacheStats{
		Entries: len(c.m), MaxEntries: c.max, ApproxBytes: approx,
		Hits: c.hits, Misses: c.misses, Evictions: c.evictions, Expired: c.expired,
	}
}

func (c *cache) withMetrics(reg *metrics.Registry) {
	if reg == nil {
		return
	}
	m := cacheMetrics{
		hits:      reg.Counter("probectl_opendata_cache_hits_total", "Open-data enrichment cache hits."),
		misses:    reg.Counter("probectl_opendata_cache_misses_total", "Open-data enrichment cache misses."),
		evictions: reg.Counter("probectl_opendata_cache_evictions_total", "Open-data enrichment cache entries evicted by the hard cap."),
		expired:   reg.Counter("probectl_opendata_cache_expired_total", "Open-data enrichment cache entries expired by TTL."),
	}
	c.mu.Lock()
	c.metrics = m
	c.mu.Unlock()
	reg.Gauge("probectl_opendata_cache_entries", "Current open-data enrichment cache entries.", func() float64 {
		return float64(c.stats().Entries)
	})
	reg.Gauge("probectl_opendata_cache_max_entries", "Configured hard maximum for open-data enrichment cache entries.", func() float64 {
		return float64(c.stats().MaxEntries)
	})
	reg.Gauge("probectl_opendata_cache_approx_bytes", "Approximate bytes represented by current open-data enrichment cache entries.", func() float64 {
		return float64(c.stats().ApproxBytes)
	})
}

func cacheEntryApproxBytes(key string, e Enrichment) int64 {
	n := 160 + len(key) + len(e.IP) + len(e.ASName) + len(e.Prefix) + len(e.CountryCode) +
		len(e.City) + len(e.RIR) + len(e.AllocationStatus) + len(e.AllocationDate)
	for _, ixp := range e.IXPs {
		n += 48 + len(ixp.Name) + len(ixp.IPv4) + len(ixp.IPv6)
	}
	for _, src := range e.Sources {
		n += 48 + len(src.Source) + len(src.License) + len(src.Attribution)
		for _, field := range src.Fields {
			n += len(field)
		}
	}
	return int64(n)
}

func (c *cache) evictExpiredLocked(now time.Time) {
	var n uint64
	for key, ent := range c.m {
		if !now.Before(ent.exp) {
			delete(c.m, key)
			n++
		}
	}
	c.recordExpiredLocked(n)
}

func (c *cache) evictOldestLocked() {
	var (
		oldestKey  string
		oldestTime time.Time
		ok         bool
	)
	for key, ent := range c.m {
		if !ok || ent.last.Before(oldestTime) {
			oldestKey, oldestTime, ok = key, ent.last, true
		}
	}
	if ok {
		delete(c.m, oldestKey)
		c.evictions++
		if c.metrics.evictions != nil {
			c.metrics.evictions.Inc()
		}
	}
}

func (c *cache) recordHitLocked() {
	c.hits++
	if c.metrics.hits != nil {
		c.metrics.hits.Inc()
	}
}

func (c *cache) recordMissLocked() {
	c.misses++
	if c.metrics.misses != nil {
		c.metrics.misses.Inc()
	}
}

func (c *cache) recordExpiredLocked(n uint64) {
	if n == 0 {
		return
	}
	c.expired += n
	if c.metrics.expired != nil {
		c.metrics.expired.Add(n)
	}
}
