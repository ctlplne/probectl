// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/apierror"
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
// down). A principal whose tenant no longer exists resolves to deleted: this
// keeps the request outside tenant-scoped handlers and their mandatory audit
// writes, which are durably fenced once a tenant is absent/offboarded. The
// storage/query boundary remains RLS; this is an earlier, clearer refusal.
type tenantStatusCache struct {
	read func(ctx context.Context, tenantID string) (string, error) // the tenants-table read
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
	read := func(ctx context.Context, tenantID string) (string, error) {
		var status string
		err := pool.QueryRow(ctx, `SELECT status FROM tenants WHERE id = $1`, tenantID).Scan(&status)
		return status, err
	}
	return &tenantStatusCache{read: read, ttl: ttl, entries: map[string]statusEntry{}}
}

// terminalStatus reports a lifecycle state that never reverses (offboarding,
// deleted): once observed it is cached for good. Suspended is NOT terminal —
// resume reverses it — so it is re-read after the TTL like active; caching it
// for good kept a resumed tenant's users refused on every replica that had
// seen the suspension. AUTHZ-22 still holds: a failed re-read serves the
// last-known status, so a status-store blip can never degrade a suspension
// back to "active".
func terminalStatus(s string) bool {
	switch s {
	case "offboarding", "deleted":
		return true
	}
	return false
}

func (c *tenantStatusCache) TenantStatus(ctx context.Context, tenantID string) (string, error) {
	c.mu.Lock()
	if e, ok := c.entries[tenantID]; ok && (terminalStatus(e.status) || time.Since(e.fetched) < c.ttl) {
		c.mu.Unlock()
		return e.status, nil
	}
	c.mu.Unlock()

	status, err := c.read(ctx, tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.mu.Lock()
			c.entries[tenantID] = statusEntry{status: "deleted", fetched: time.Now()}
			c.mu.Unlock()
			return "deleted", nil
		}
		// AUTHZ-22: serve stale ONLY when we have prior knowledge of this tenant
		// (a transient blip after a successful read keeps the API up). With an
		// EMPTY cache a lookup error must FAIL CLOSED — returning "active" here
		// would serve a suspended/offboarded tenant on a fresh replica whose
		// status read happens to fail. RLS still protects data independently;
		// this refuses the request earlier, at the lifecycle gate.
		c.mu.Lock()
		defer c.mu.Unlock()
		if e, ok := c.entries[tenantID]; ok {
			return e.status, nil
		}
		return "", err
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
		// AUTHZ-22: the lifecycle state is unknown (no cached value, lookup
		// failed). Fail closed with a retryable 503 (the registered "unavailable"
		// code) rather than assume active — a suspended tenant must not be served
		// just because its status read failed on a fresh replica.
		return apierror.Unavailable("tenant lifecycle state is temporarily unavailable")
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
