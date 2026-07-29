// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// abacCache caches each tenant's ABAC policies for a short TTL so the per-request
// permission check (S31) doesn't hit Postgres on every call. Policy CRUD
// invalidates the tenant's entry; deprovision revocation does NOT depend on this
// cache (it deletes sessions directly), so a deprovisioned user is locked out at
// once regardless of the TTL.
type abacCache struct {
	mu   sync.Mutex
	pool *pgxpool.Pool
	ttl  time.Duration
	data map[string]abacEntry
}

type abacEntry struct {
	policies []auth.Policy
	expiry   time.Time
}

func newABACCache(pool *pgxpool.Pool) *abacCache {
	return &abacCache{pool: pool, ttl: 30 * time.Second, data: map[string]abacEntry{}}
}

// policies returns a tenant's ABAC policies, loading + caching on a miss. Any
// load failure is returned to the authorization caller so it can fail closed.
// An entry is authoritative only until its expiry; serving it after a failed
// refresh could preserve an allow after another replica installed a deny.
func (c *abacCache) policies(ctx context.Context, tenantID string) ([]auth.Policy, error) {
	if c == nil || c.pool == nil {
		return nil, nil
	}
	c.mu.Lock()
	e, ok := c.data[tenantID]
	c.mu.Unlock()
	if ok && time.Now().Before(e.expiry) {
		return e.policies, nil
	}
	var pols []auth.Policy
	loadErr := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), c.pool, func(ctx context.Context, sc tenancy.Scope) error {
		p, err := store.ABACPolicies{}.List(ctx, sc)
		if err == nil {
			pols = p
		}
		return err
	})
	if loadErr != nil {
		// CODE-002: a transient scope-setup/query fault must NOT be cached as
		// "no policies" — that would poison the cache for the whole TTL and
		// silently widen access (an empty policy set). An expired entry is not a
		// safe fallback either: another replica may have installed a new deny
		// since it was loaded. Surface every refresh failure so authorization
		// refuses the request. tenancy.InTenant sets the scope BEFORE running fn,
		// so a setup failure cannot leak another tenant's rows (fail closed).
		logging.FromContext(ctx).Warn("ABAC policy refresh failed; refusing expired policy state",
			"tenant_id", tenantID, "error", loadErr.Error())
		return nil, loadErr
	}
	c.mu.Lock()
	c.data[tenantID] = abacEntry{policies: pols, expiry: time.Now().Add(c.ttl)}
	c.mu.Unlock()
	return pols, nil
}

func (c *abacCache) invalidate(tenantID string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.data, tenantID)
	c.mu.Unlock()
}

// abacDenies reports whether a tenant's ABAC policies deny a permission for the
// principal (after RBAC has already permitted it). resource is nil for routes
// that carry no resource attributes.
func (s *Server) abacDenies(ctx context.Context, p *auth.Principal, perm string, resource map[string]string) (bool, error) {
	if s.abac == nil {
		return false, nil
	}
	policies, err := s.abac.policies(ctx, p.TenantID)
	if err != nil {
		return false, apierror.Unavailable("authorization policy is temporarily unavailable").Wrap(err)
	}
	return auth.Evaluate(policies, perm, p.Attributes, resource) == auth.PolicyDeny, nil
}

// --- /v1/abac/policies admin (the ABAC policy model contract) ---

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) error {
	var out []auth.Policy
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		p, e := store.ABACPolicies{}.ListAdminPage(ctx, sc, 500)
		out = p
		return e
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
	return nil
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) error {
	var req auth.Policy
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if req.Effect != auth.PolicyAllow && req.Effect != auth.PolicyDeny {
		return apierror.Validation("effect must be \"allow\" or \"deny\"")
	}
	var created *auth.Policy
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		p, e := store.ABACPolicies{}.Create(ctx, sc, req)
		if e != nil {
			return e
		}
		created = p
		return s.recordAudit(ctx, sc, r, "abac.policy_create", p.ID, map[string]any{"effect": string(p.Effect), "permission": p.Permission})
	}); err != nil {
		return err
	}
	s.abac.invalidate(tenantOf(r)) // policy changed — drop the tenant's cached set
	w.Header().Set("Location", "/v1/abac/policies/"+created.ID)
	writeJSON(w, http.StatusCreated, created)
	return nil
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if e := (store.ABACPolicies{}).Delete(ctx, sc, id); e != nil {
			return e
		}
		return s.recordAudit(ctx, sc, r, "abac.policy_delete", id, nil)
	}); err != nil {
		return err
	}
	s.abac.invalidate(tenantOf(r))
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func tenantOf(r *http.Request) string {
	if p := auth.PrincipalFrom(r.Context()); p != nil {
		return p.TenantID
	}
	return ""
}
