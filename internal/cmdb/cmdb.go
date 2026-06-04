// Package cmdb correlates probectl assets and incidents with configuration
// items (CIs) in an external CMDB (S40, F30; ServiceNow first).
//
// Shape: a Provider looks up CIs by key (an IP address or hostname); the
// Resolver wraps it with a TTL cache, negative caching, and graceful
// degradation (a down CMDB serves stale entries and never breaks core
// function — CLAUDE.md §7 guardrail 10). Correlation is read-only: probectl
// never writes to the CMDB. Credentials come from the environment — never
// config files or logs (guardrail 6); lookups ride TLS with certificate
// verification (guardrail 12). The CMDB itself is deployment-level
// infrastructure, but every correlation REQUEST is tenant-scoped by the
// caller (the control plane resolves keys from the caller's own tenant's
// incidents/agents only).
package cmdb

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// CI is one configuration item.
type CI struct {
	SysID     string            `json:"sys_id"`
	Name      string            `json:"name"`
	Class     string            `json:"class,omitempty"`
	IPAddress string            `json:"ip_address,omitempty"`
	FQDN      string            `json:"fqdn,omitempty"`
	URL       string            `json:"url,omitempty"` // deep link into the CMDB UI
	Extra     map[string]string `json:"extra,omitempty"`
}

// Provider looks up CIs by key (IP address or hostname/FQDN).
type Provider interface {
	Name() string
	Lookup(ctx context.Context, key string) ([]CI, error)
}

// Match is the correlation result for one key.
type Match struct {
	Key string `json:"key"`
	CIs []CI   `json:"cis"`
}

// ErrUnavailable reports that the CMDB could not be reached and no cached
// answer exists. Callers degrade gracefully (the data is enrichment, not core).
var ErrUnavailable = errors.New("cmdb: provider unavailable")

type cacheEntry struct {
	cis     []CI
	fetched time.Time
}

// Resolver wraps a Provider with caching + graceful degradation.
type Resolver struct {
	provider Provider
	ttl      time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// NewResolver wraps provider with a TTL cache (default 10m when ttl <= 0).
func NewResolver(provider Provider, ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Resolver{provider: provider, ttl: ttl, cache: map[string]cacheEntry{}}
}

// ProviderName names the wrapped provider (for API responses/logs).
func (r *Resolver) ProviderName() string { return r.provider.Name() }

// Lookup resolves one key, serving fresh cache hits first. On provider error a
// stale cache entry (if any) is served — a down CMDB must not break probectl.
func (r *Resolver) Lookup(ctx context.Context, key string) ([]CI, error) {
	key = CanonicalKey(key)
	if key == "" {
		return nil, nil
	}
	r.mu.Lock()
	entry, ok := r.cache[key]
	r.mu.Unlock()
	if ok && time.Since(entry.fetched) < r.ttl {
		return entry.cis, nil
	}
	cis, err := r.provider.Lookup(ctx, key)
	if err != nil {
		if ok { // graceful degrade: stale beats nothing
			return entry.cis, nil
		}
		return nil, errors.Join(ErrUnavailable, err)
	}
	r.mu.Lock()
	r.cache[key] = cacheEntry{cis: cis, fetched: time.Now()} // negative results cached too
	r.mu.Unlock()
	return cis, nil
}

// Correlate resolves every key (deduplicated, canonicalized) and returns the
// keys that matched at least one CI. Lookup errors skip the key — correlation
// is best-effort enrichment.
func (r *Resolver) Correlate(ctx context.Context, keys []string) []Match {
	seen := map[string]bool{}
	var out []Match
	for _, k := range keys {
		ck := CanonicalKey(k)
		if ck == "" || seen[ck] {
			continue
		}
		seen[ck] = true
		cis, err := r.Lookup(ctx, ck)
		if err != nil || len(cis) == 0 {
			continue
		}
		out = append(out, Match{Key: ck, CIs: cis})
	}
	return out
}

// CanonicalKey normalizes a correlation key: trims, lowercases hostnames,
// strips ports/schemes, and rejects values that are neither an IP address nor
// a plausible hostname (CIDR prefixes and free-form text are not CI keys).
func CanonicalKey(key string) string {
	k := strings.TrimSpace(strings.ToLower(key))
	hadScheme := strings.HasPrefix(k, "https://") || strings.HasPrefix(k, "http://")
	k = strings.TrimPrefix(k, "https://")
	k = strings.TrimPrefix(k, "http://")
	if i := strings.IndexByte(k, '/'); i >= 0 {
		if !hadScheme {
			return "" // a bare slash is a CIDR prefix or garbage, not a CI key
		}
		k = k[:i]
	}
	// Strip a :port (but not from a bare IPv6 address).
	if h, _, ok := splitHostPort(k); ok {
		k = h
	}
	if k == "" || strings.Contains(k, "/") {
		return ""
	}
	if addr, err := netip.ParseAddr(k); err == nil {
		return addr.String()
	}
	if isHostname(k) {
		return k
	}
	return ""
}

func splitHostPort(s string) (string, string, bool) {
	if strings.HasPrefix(s, "[") { // [v6]:port
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return "", "", false
		}
		if end+1 < len(s) && s[end+1] == ':' {
			return s[1:end], s[end+2:], true
		}
		return s[1:end], "", true
	}
	if strings.Count(s, ":") == 1 { // host:port (not bare IPv6)
		i := strings.IndexByte(s, ':')
		return s[:i], s[i+1:], true
	}
	return "", "", false
}

func isHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, lbl := range strings.Split(s, ".") {
		if len(lbl) == 0 || len(lbl) > 63 {
			return false
		}
		for i := 0; i < len(lbl); i++ {
			c := lbl[i]
			ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
			if !ok || (c == '-' && (i == 0 || i == len(lbl)-1)) {
				return false
			}
		}
	}
	return true
}
