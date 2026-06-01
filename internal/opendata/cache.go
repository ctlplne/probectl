package opendata

import (
	"sync"
	"time"
)

// cache is a small TTL cache of enrichment results, keyed by IP. It exists to
// shield rate-limited / slow upstreams: an IP looked up twice within the TTL is
// served from memory (S15 watch-out — cache aggressively).
type cache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]cacheEntry
}

type cacheEntry struct {
	e   Enrichment
	exp time.Time
}

func newCache(ttl time.Duration) *cache {
	return &cache{ttl: ttl, m: make(map[string]cacheEntry)}
}

func (c *cache) get(key string) (Enrichment, bool) {
	if c.ttl <= 0 {
		return Enrichment{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ent, ok := c.m[key]
	if !ok || time.Now().After(ent.exp) {
		return Enrichment{}, false
	}
	return ent.e, true
}

func (c *cache) put(key string, e Enrichment) {
	if c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = cacheEntry{e: e, exp: time.Now().Add(c.ttl)}
}
