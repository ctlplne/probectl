package control

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
)

// Tenant lifecycle enforcement (S-T1). When the provider plane suspends or
// offboards a tenant, that tenant's API access stops. The check runs in
// requirePermission — after the principal (tenant-first), before the handler —
// keyed STRICTLY by the principal's own tenant (it can never consult another
// tenant's status, so it cannot become a cross-tenant probe).
//
// Semantics: suspension blocks the tenant's USERS at the API; it does not
// destroy data or stop ingestion pipelines (suspension is a billing/lifecycle
// state, not deletion — see docs/provider-plane.md). Verifiable deletion is
// S-T5.

// TenantStatusSource reports a tenant's lifecycle status ("active",
// "suspended", "offboarding", "deleted"). Implementations must be cheap —
// requirePermission consults it per request.
type TenantStatusSource interface {
	TenantStatus(ctx context.Context, tenantID string) (string, error)
}

// tenantStatusCache is a small TTL cache over the tenants table. On a read
// error it serves the last-known status (a DB blip must not take the API
// down); a tenant never seen resolves to active (lifecycle gating is an
// administrative state — the SECURITY boundary remains RLS, which fails
// closed on its own).
type tenantStatusCache struct {
	pool *pgxpool.Pool
	ttl  time.Duration

	mu      sync.Mutex
	entries map[string]statusEntry
}

type statusEntry struct {
	status  string
	fetched time.Time
}

// NewTenantStatusCache builds the production source over the tenants table.
func NewTenantStatusCache(pool *pgxpool.Pool, ttl time.Duration) TenantStatusSource {
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	return &tenantStatusCache{pool: pool, ttl: ttl, entries: map[string]statusEntry{}}
}

func (c *tenantStatusCache) TenantStatus(ctx context.Context, tenantID string) (string, error) {
	c.mu.Lock()
	if e, ok := c.entries[tenantID]; ok && time.Since(e.fetched) < c.ttl {
		c.mu.Unlock()
		return e.status, nil
	}
	c.mu.Unlock()

	var status string
	err := c.pool.QueryRow(ctx, `SELECT status FROM tenants WHERE id = $1`, tenantID).Scan(&status)
	if err != nil {
		// Serve stale on error; absent any knowledge, treat as active.
		c.mu.Lock()
		defer c.mu.Unlock()
		if e, ok := c.entries[tenantID]; ok {
			return e.status, nil
		}
		return "active", nil //nolint:nilerr // deliberate: degrade open for lifecycle (not isolation) state
	}
	c.mu.Lock()
	c.entries[tenantID] = statusEntry{status: status, fetched: time.Now()}
	c.mu.Unlock()
	return status, nil
}

// WithTenantStatus attaches the lifecycle source. nil is a no-op (unit tests /
// dev mode); main wires the cache whenever a pool exists.
func (s *Server) WithTenantStatus(src TenantStatusSource) *Server {
	s.tenantStatus = src
	return s
}

// checkTenantLifecycle rejects requests from suspended/offboarded tenants.
func (s *Server) checkTenantLifecycle(r *http.Request, tenantID string) error {
	if s.tenantStatus == nil || tenantID == "" {
		return nil
	}
	status, err := s.tenantStatus.TenantStatus(r.Context(), tenantID)
	if err != nil {
		return nil // degrade open: lifecycle gating must not amplify a DB blip
	}
	switch status {
	case "suspended":
		return apierror.Forbidden("tenant is suspended").WithCode("tenant_suspended")
	case "offboarding", "deleted":
		return apierror.Forbidden("tenant is offboarded").WithCode("tenant_offboarded")
	default:
		return nil
	}
}
