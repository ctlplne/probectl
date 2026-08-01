// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
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
	// generations is the correctness half: invalidation bumps a tenant's
	// generation, so a load begun before a committed policy change can never
	// publish afterward. singleflight cannot express that — it dedups, it does
	// not know when its result went stale — so the two compose rather than one
	// replacing the other.
	generations map[string]uint64
	// fill is the DEDUP half, and is the sanctioned idiom rather than a
	// hand-rolled one (docs/architecture.md, "Concurrency idioms"): concurrent
	// misses for one tenant share a single store read instead of each opening
	// its own tenant-scoped transaction. On a cold cache under load that is the
	// difference between one query and one query per in-flight request.
	fill singleflight.Group
	load func(context.Context, string) ([]auth.Policy, error)
}

type abacEntry struct {
	policies []auth.Policy
	expiry   time.Time
}

func newABACCache(pool *pgxpool.Pool) *abacCache {
	cache := &abacCache{
		pool:        pool,
		ttl:         30 * time.Second,
		data:        map[string]abacEntry{},
		generations: map[string]uint64{},
	}
	cache.load = cache.loadFromStore
	return cache
}

const abacLoadAttempts = 2

// abacLoadTimeout bounds the shared fill. The fill runs on a context DETACHED
// from the leader's request: with singleflight the first caller's cancellation
// would otherwise fail every waiter closed, turning one client hanging up into
// a burst of refused authorizations. Detaching needs a ceiling of its own so a
// stuck database cannot pin the tenant's singleflight key indefinitely.
const abacLoadTimeout = 5 * time.Second

var errABACInvalidatedDuringLoad = errors.New("ABAC policy cache invalidated during refresh")

// policies returns a tenant's ABAC policies, loading + caching on a miss. Any
// load failure is returned to the authorization caller so it can fail closed.
// An entry is authoritative only until its expiry; serving it after a failed
// refresh could preserve an allow after another replica installed a deny. Each
// fill is also generation-bound: invalidation increments the tenant generation,
// so a load begun before a committed policy change can never publish afterward.
func (c *abacCache) policies(ctx context.Context, tenantID string) ([]auth.Policy, error) {
	if c == nil {
		return nil, nil
	}
	load := c.load
	if load == nil {
		if c.pool == nil {
			return nil, nil
		}
		load = c.loadFromStore
	}

	if pols, ok := c.fresh(tenantID); ok {
		return pols, nil
	}
	// One store read per tenant, shared by every concurrent miss. The result is
	// NOT cached by singleflight: an error is returned to each waiter (fail
	// closed) and the next request retries.
	v, err, _ := c.fill.Do(tenantID, func() (any, error) {
		fillCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), abacLoadTimeout)
		defer cancel()
		return c.fillOnce(fillCtx, tenantID, load)
	})
	if err != nil {
		return nil, err
	}
	pols, _ := v.([]auth.Policy)
	return pols, nil
}

// fresh returns a tenant's policies when the cached entry is still
// authoritative.
func (c *abacCache) fresh(tenantID string) ([]auth.Policy, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.data[tenantID]
	if ok && time.Now().Before(e.expiry) {
		return e.policies, true
	}
	return nil, false
}

// fillOnce is the body singleflight shares: load, then publish only if the
// tenant's generation did not move while the read was in flight.
func (c *abacCache) fillOnce(ctx context.Context, tenantID string, load func(context.Context, string) ([]auth.Policy, error)) ([]auth.Policy, error) {
	for attempt := 0; attempt < abacLoadAttempts; attempt++ {
		c.mu.Lock()
		e, ok := c.data[tenantID]
		generation := c.generations[tenantID]
		c.mu.Unlock()
		if ok && time.Now().Before(e.expiry) {
			return e.policies, nil
		}

		pols, loadErr := load(ctx, tenantID)
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
		if c.generations[tenantID] != generation {
			// A committed mutation invalidated this tenant while the store read
			// was in flight. Discard the obsolete snapshot and retry from the new
			// generation; it must never receive a fresh authoritative TTL.
			c.mu.Unlock()
			continue
		}
		if c.data == nil {
			c.data = map[string]abacEntry{}
		}
		c.data[tenantID] = abacEntry{policies: pols, expiry: time.Now().Add(c.ttl)}
		c.mu.Unlock()
		return pols, nil
	}

	// Repeated policy churn won both bounded publication attempts. Authorization
	// must fail closed instead of spinning indefinitely or accepting any snapshot.
	return nil, errABACInvalidatedDuringLoad
}

func (c *abacCache) loadFromStore(ctx context.Context, tenantID string) ([]auth.Policy, error) {
	if c.pool == nil {
		return nil, nil
	}
	var pols []auth.Policy
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), c.pool, func(ctx context.Context, sc tenancy.Scope) error {
		p, err := store.ABACPolicies{}.List(ctx, sc)
		if err == nil {
			pols = p
		}
		return err
	})
	return pols, err
}

func (c *abacCache) invalidate(tenantID string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.generations == nil {
		c.generations = map[string]uint64{}
	}
	c.generations[tenantID]++
	delete(c.data, tenantID)
	c.mu.Unlock()
}

// decide is the control plane's single authorization door (S-6357f747): it
// loads the tenant's ABAC policies FAIL CLOSED (a load failure is an error,
// never RBAC-only access) and evaluates the documented order — tenant
// boundary, then RBAC per mode, then ABAC deny — through auth.Decide, the one
// evaluator every surface shares. Route middleware, Explorer sources, canary
// overrides, IR attribution, incident sharing, onboarding checks and
// authoring extras all pass here; the authz-chokepoint gate bans new direct
// uses of the underlying evaluation primitives outside this file.
func (s *Server) decide(ctx context.Context, p *auth.Principal, perm string, mode auth.RBACCheck, resource map[string]string) (auth.DecisionReason, error) {
	var policies []auth.Policy
	if s.abac != nil && p != nil {
		loaded, err := s.abac.policies(ctx, p.TenantID)
		if err != nil {
			return auth.DecisionPolicyDeny, apierror.Unavailable("authorization policy is temporarily unavailable").Wrap(err)
		}
		policies = loaded
	}
	return auth.Decide(p, perm, mode, policies, resource), nil
}

// authorize is decide with the standard error mapping for handlers that need
// no per-layer copy: 401 unauthenticated, 403 with the layer's phrasing.
func (s *Server) authorize(ctx context.Context, p *auth.Principal, perm string, mode auth.RBACCheck, resource map[string]string) error {
	reason, err := s.decide(ctx, p, perm, mode, resource)
	if err != nil {
		return err
	}
	switch reason {
	case auth.DecisionAllowed:
		return nil
	case auth.DecisionUnauthenticated:
		return apierror.Unauthorized("authentication required")
	case auth.DecisionTenantBoundary:
		return apierror.Forbidden("resource belongs to another tenant")
	case auth.DecisionRBAC:
		return apierror.Forbidden("missing permission: " + perm)
	default:
		return apierror.Forbidden("denied by an attribute policy: " + perm)
	}
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
