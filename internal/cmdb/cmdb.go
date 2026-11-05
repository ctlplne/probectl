// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package cmdb correlates probectl assets and incidents with configuration
// items (CIs) in an external CMDB (S40, F30; ServiceNow first).
//
// Shape: a Provider looks up CIs by key (an IP address or hostname); the
// Resolver wraps it with a TTL cache, negative caching, and graceful
// degradation (a down CMDB serves stale entries and never breaks core
// function — docs/guardrails.md G7-10). Correlation is read-only: probectl
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

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
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
	// Relations are not projected by enrichment. Reviewed import may follow
	// their exact IDs only after separately proving the related CI's tenant.
	relatedKind string
	relatedID   int64
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
	// epochs prevent a source read started before an ownership refusal from
	// restoring that key's revoked stale enrichment when it completes later.
	epochs map[string]uint64
}

// NewResolver wraps provider with a TTL cache (default 10m when ttl <= 0).
func NewResolver(provider Provider, ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Resolver{provider: provider, ttl: ttl, cache: map[string]cacheEntry{}, epochs: map[string]uint64{}}
}

// ProviderName names the wrapped provider (for API responses/logs).
func (r *Resolver) ProviderName() string { return r.provider.Name() }

func lookupTenant(ctx context.Context) (tenancy.ID, error) {
	if ctx == nil {
		return "", ErrTenantBinding
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return "", ErrTenantBinding
	}
	id, err := uuid.Parse(tenant.String())
	if err != nil || id == uuid.Nil || id.String() != tenant.String() {
		return "", ErrTenantBinding
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return tenant, nil
}

// Lookup resolves one key, serving fresh cache hits first. Availability errors
// may use a complete stale entry; binding and incomplete-result errors revoke it.
func (r *Resolver) Lookup(ctx context.Context, key string) ([]CI, error) {
	tenant, err := lookupTenant(ctx)
	if err != nil {
		return nil, err
	}
	key = CanonicalKey(key)
	if key == "" {
		return nil, nil
	}
	cacheKey := tenant.String() + "\x00" + key
	if scoped, ok := r.provider.(interface {
		cacheScope(context.Context) (string, error)
	}); ok {
		scope, err := scoped.cacheScope(ctx)
		if err != nil {
			return nil, err
		}
		cacheKey = scope + "\x00" + key
	}
	r.mu.Lock()
	entry, ok := r.cache[cacheKey]
	epoch := r.epochs[cacheKey]
	r.mu.Unlock()
	if ok && time.Since(entry.fetched) < r.ttl {
		return entry.cis, nil
	}
	cis, err := r.lookupFresh(ctx, key)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		if errors.Is(err, ErrTenantBinding) || errors.Is(err, ErrLookupBudget) || errors.Is(err, ErrLookupIncomplete) {
			r.epochs[cacheKey]++
			delete(r.cache, cacheKey)
			return nil, err
		}
		if canceled := ctx.Err(); canceled != nil {
			return nil, canceled
		}
		if epoch != r.epochs[cacheKey] {
			return nil, ErrTenantBinding
		}
		if current, exists := r.cache[cacheKey]; exists { // stale remains authorized
			return current.cis, nil
		}
		return nil, errors.Join(ErrUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if epoch != r.epochs[cacheKey] {
		return nil, ErrTenantBinding
	}
	r.cache[cacheKey] = cacheEntry{cis: cis, fetched: time.Now()} // negative results cached too
	return cis, nil
}

// lookupFresh is the uncached provider read used on cache misses. A provider
// outage returns an error here; only Lookup may choose a stale enrichment
// answer. Reviewed import paths must use an uncached read after tenant binding.
func (r *Resolver) lookupFresh(ctx context.Context, key string) ([]CI, error) {
	if r == nil || r.provider == nil {
		return nil, ErrUnavailable
	}
	key = CanonicalKey(key)
	if key == "" {
		return nil, errors.New("cmdb: invalid lookup key")
	}
	return r.provider.Lookup(ctx, key)
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
