// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package billing

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/usage"
)

// QuotaChecker implements usage.QuotaChecker over the quota store + live
// per-tenant counts. Live counting (inside the tenant's own scope) keeps the
// gate exact — billing-critical accuracy beats cache staleness; creates are
// rare and the counts are tenant-indexed. Quota LOOKUPS cache briefly.
//
// Semantics (the house doctrine): quotas gate control-plane RESOURCE
// CREATION only. Telemetry is never quota-dropped; re-registration of an
// existing agent is never rejected (the call sites enforce that). A lookup
// or count failure ALLOWS the create (degrade open): quota is a billing
// control, not a security boundary — availability wins on infrastructure
// blips, and the metering trail still records what happened.
type QuotaChecker struct {
	store Store
	count TenantCounter
	ttl   time.Duration
	now   func() time.Time

	mu     sync.Mutex
	cache  map[string]cachedQuota
	misses int
}

type cachedQuota struct {
	q       Quota
	fetched time.Time
}

// NewQuotaChecker wires the gate.
func NewQuotaChecker(store Store, count TenantCounter, ttl time.Duration) *QuotaChecker {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &QuotaChecker{store: store, count: count, ttl: ttl, now: time.Now, cache: map[string]cachedQuota{}}
}

func (c *QuotaChecker) quota(ctx context.Context, tenantID string) (Quota, error) {
	c.mu.Lock()
	if e, ok := c.cache[tenantID]; ok && c.now().Sub(e.fetched) < c.ttl {
		c.mu.Unlock()
		return e.q, nil
	}
	c.mu.Unlock()
	q, err := c.store.QuotaFor(ctx, tenantID)
	if err != nil {
		return Quota{}, err
	}
	c.mu.Lock()
	c.cache[tenantID] = cachedQuota{q: q, fetched: c.now()}
	c.mu.Unlock()
	return q, nil
}

// Invalidate drops a tenant's cached quota (after a quota update).
func (c *QuotaChecker) Invalidate(tenantID string) {
	c.mu.Lock()
	delete(c.cache, tenantID)
	c.mu.Unlock()
}

// AllowCreate implements usage.QuotaChecker.
func (c *QuotaChecker) AllowCreate(ctx context.Context, tenantID, resource string) error {
	q, err := c.quota(ctx, tenantID)
	if err != nil {
		return nil // degrade open: a billing control must not amplify a DB blip
	}
	var limit *int
	switch resource {
	case usage.MeterAgents:
		limit = q.MaxAgents
	case usage.MeterTests:
		limit = q.MaxTests
	default:
		return nil
	}
	if limit == nil {
		return nil // unlimited
	}
	agents, tests, err := c.count(ctx, tenantID)
	if err != nil {
		return nil // degrade open
	}
	current := agents
	if resource == usage.MeterTests {
		current = tests
	}
	if current >= int64(*limit) {
		return fmt.Errorf("tenant quota exhausted: %d of %d %s in use (raise the quota in the provider console)",
			current, *limit, resource)
	}
	return nil
}
