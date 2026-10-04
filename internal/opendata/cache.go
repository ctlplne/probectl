// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"container/list"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/metrics"
)

// DefaultCacheMaxEntries is the process-wide safety wall for the shared
// enrichment cache. It is deliberately finite: open-data enrichment is shared
// across tenants, so distinct-IP floods must evict instead of growing memory
// without bound.
const DefaultCacheMaxEntries = 65536

// cache is a small TTL cache of enrichment results, keyed by IP. It exists to
// shield rate-limited / slow upstreams: an IP looked up twice within the TTL is
// served from memory (S15 watch-out — cache aggressively).
//
// It is an O(1) LRU: a doubly linked list (front = most-recently-used, back =
// least-recently-used) threaded through a map[key]*list.Element. get/put move
// the touched entry to the front; a put at capacity evicts the back. There is
// no O(n) scan on the hot path — a single tenant's distinct-IP churn can no
// longer serialize deployment-wide enrichment behind a full-map sweep under the
// shared lock (docs/guardrails.md G7-10 — open-data enrichment stays per-tenant
// fair and gracefully degrades). Expiry is lazy: an entry is checked on get and
// the back is checked when it is evicted, so stale entries cost nothing until
// they are touched.
type cache struct {
	mu  sync.Mutex
	ttl time.Duration
	max int
	ll  *list.List               // front = MRU, back = LRU
	m   map[string]*list.Element // key -> element holding *cacheEntry
	now func() time.Time

	hits, misses, evictions, expired uint64
	// scans counts cache entries examined while deciding an overflow eviction.
	// The O(1) LRU looks at a constant number of entries per capacity insert
	// (the back of the list); the previous full-map-scan eviction examined
	// ~len(m) entries per insert. The regression test asserts this stays O(1).
	scans   uint64
	metrics cacheMetrics
}

type cacheEntry struct {
	key string
	e   Enrichment
	exp time.Time
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
	return &cache{
		ttl: ttl,
		max: DefaultCacheMaxEntries,
		ll:  list.New(),
		m:   make(map[string]*list.Element),
		now: time.Now,
	}
}

func (c *cache) get(key string) (Enrichment, bool) {
	if c.ttl <= 0 || c.max <= 0 {
		return Enrichment{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	el, ok := c.m[key]
	if !ok {
		c.recordMissLocked()
		return Enrichment{}, false
	}
	ent := el.Value.(*cacheEntry)
	if !now.Before(ent.exp) {
		c.removeElementLocked(el)
		c.recordExpiredLocked(1)
		c.recordMissLocked()
		return Enrichment{}, false
	}
	c.ll.MoveToFront(el)
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
	if el, exists := c.m[key]; exists {
		ent := el.Value.(*cacheEntry)
		ent.e = e
		ent.exp = now.Add(c.ttl)
		c.ll.MoveToFront(el)
		return
	}
	if len(c.m) >= c.max {
		c.evictOverflowLocked(now)
	}
	el := c.ll.PushFront(&cacheEntry{key: key, e: e, exp: now.Add(c.ttl)})
	c.m[key] = el
}

func (c *cache) setTTL(ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttl = ttl
	if ttl <= 0 {
		c.resetLocked()
	}
}

func (c *cache) setMax(limit int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.max = limit
	if limit <= 0 {
		c.resetLocked()
		return
	}
	// Config change (cold path): sweep expired entries once, then trim the LRU
	// tail down to the new cap. Each removal is O(1); this is not the hot path.
	c.sweepExpiredLocked(c.now())
	for len(c.m) > limit {
		if !c.evictBackLocked() {
			break
		}
	}
}

func (c *cache) stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	var approx int64
	for key, el := range c.m {
		approx += cacheEntryApproxBytes(key, el.Value.(*cacheEntry).e)
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

// evictOverflowLocked makes room for one new key when the cache is at capacity.
// It examines the least-recently-used entry (the back of the list) and nothing
// else — O(1), independent of len(m) — counting one scan. If that entry is
// already expired it is accounted as an expiry; otherwise it is a cap eviction.
func (c *cache) evictOverflowLocked(now time.Time) {
	el := c.ll.Back()
	if el == nil {
		return
	}
	c.scans++
	ent := el.Value.(*cacheEntry)
	if !now.Before(ent.exp) {
		c.removeElementLocked(el)
		c.recordExpiredLocked(1)
		return
	}
	c.removeElementLocked(el)
	c.recordEvictionLocked()
}

// evictBackLocked drops the least-recently-used entry as a cap eviction. Used by
// the cold setMax trim path. Returns false when the cache is already empty.
func (c *cache) evictBackLocked() bool {
	el := c.ll.Back()
	if el == nil {
		return false
	}
	c.removeElementLocked(el)
	c.recordEvictionLocked()
	return true
}

// sweepExpiredLocked removes every expired entry. It is O(n) and only called
// from the cold setMax reconfiguration path, never from get/put.
func (c *cache) sweepExpiredLocked(now time.Time) {
	var n uint64
	for el := c.ll.Back(); el != nil; {
		prev := el.Prev()
		if ent := el.Value.(*cacheEntry); !now.Before(ent.exp) {
			c.removeElementLocked(el)
			n++
		}
		el = prev
	}
	c.recordExpiredLocked(n)
}

func (c *cache) removeElementLocked(el *list.Element) {
	ent := el.Value.(*cacheEntry)
	c.ll.Remove(el)
	delete(c.m, ent.key)
}

func (c *cache) resetLocked() {
	c.ll = list.New()
	c.m = make(map[string]*list.Element)
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

func (c *cache) recordEvictionLocked() {
	c.evictions++
	if c.metrics.evictions != nil {
		c.metrics.evictions.Inc()
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
