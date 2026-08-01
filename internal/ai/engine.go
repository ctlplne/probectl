// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ai

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
)

// Engine errors.
var (
	ErrNoTenant = errors.New("ai: no tenant on principal (fail closed)")
	// ErrBusy means the process-wide Analyze concurrency cap is saturated
	// (U-048) — the API maps it to 429 so callers back off, never queue.
	ErrBusy          = errors.New("ai: analyzer at capacity")
	ErrForbidden     = errors.New("ai: forbidden — insufficient permission")
	ErrUnknownDomain = errors.New("ai: unknown query domain")
	ErrNoSource      = errors.New("ai: no source configured for domain")
)

// Engine is probectl's unified semantic query layer — THE tenant-then-RBAC/ABAC
// security boundary for the API, the AI/RCA layer (S24), and the MCP server
// (S25). It takes the tenant from the authenticated principal (never the query),
// enforces each source permission, applies cost/timeout guards, and dispatches
// to the store sources, returning a normalized envelope with provenance.
type Engine struct {
	metrics  MetricsSource
	events   EventsSource
	entities EntitiesSource
	topology TopologySource

	maxRows             int
	timeout             time.Duration
	permissionAuthorize PermissionAuthorizer
}

// Option configures an Engine.
type Option func(*Engine)

// PermissionAuthorizer applies the deployment's policy layer after the engine
// has established a non-empty tenant and an RBAC grant. Returning an error
// means policy state could not be loaded and the evidence read must fail closed.
type PermissionAuthorizer func(context.Context, *auth.Principal, string) (bool, error)

// WithMetrics / WithEvents / WithEntities / WithTopology register store sources.
func WithMetrics(s MetricsSource) Option   { return func(e *Engine) { e.metrics = s } }
func WithEvents(s EventsSource) Option     { return func(e *Engine) { e.events = s } }
func WithEntities(s EntitiesSource) Option { return func(e *Engine) { e.entities = s } }
func WithTopology(s TopologySource) Option { return func(e *Engine) { e.topology = s } }

// WithPermissionAuthorizer adds the tenant ABAC deny-override used by shipping
// API and MCP engines. A nil authorizer leaves the engine's existing
// tenant-first + RBAC behavior for isolated/offline callers with no policy
// store.
func WithPermissionAuthorizer(authorize PermissionAuthorizer) Option {
	return func(e *Engine) { e.permissionAuthorize = authorize }
}

// WithMaxRows / WithTimeout set the cost guards.
func WithMaxRows(n int) Option {
	return func(e *Engine) {
		if n > 0 {
			e.maxRows = n
		}
	}
}

func WithTimeout(d time.Duration) Option {
	return func(e *Engine) {
		if d > 0 {
			e.timeout = d
		}
	}
}

// NewEngine builds an Engine with the given sources and guards.
func NewEngine(opts ...Option) *Engine {
	e := &Engine{maxRows: 1000, timeout: 30 * time.Second}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Query runs a single-domain query under the principal's tenant and permission
// policy. The tenant boundary is enforced FIRST (from the principal, never the
// query), then RBAC, then the configured ABAC deny-override; all fail closed.
func (e *Engine) Query(ctx context.Context, p *auth.Principal, q Query) (Result, error) {
	if p == nil || p.TenantID == "" {
		return Result{}, ErrNoTenant
	}
	perm := permissionFor(q.Domain)
	if perm == "" {
		return Result{}, ErrUnknownDomain
	}
	allowed, err := e.authorized(ctx, p, perm)
	if err != nil {
		return Result{}, fmt.Errorf("ai: authorize %s: %w", perm, err)
	}
	if !allowed {
		return Result{}, ErrForbidden
	}

	limit := e.capLimit(q.Limit)
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	start := time.Now()
	rows, err := e.dispatch(ctx, p.TenantID, q, limit)
	if err != nil {
		return Result{}, err
	}
	res := Result{Tenant: p.TenantID, Domains: []Domain{q.Domain}, Elapsed: time.Since(start)}
	if len(rows) > limit {
		rows, res.Truncated = rows[:limit], true
	}
	res.Rows = rows
	return res, nil
}

// Correlate fans a subject across every domain the principal may read after
// RBAC+ABAC and returns one envelope with per-domain provenance — the cross-store
// join. Domains the caller cannot read are silently skipped, so a correlation
// never leaks out-of-scope data.
func (e *Engine) Correlate(ctx context.Context, p *auth.Principal, subject map[string]string, r TimeRange) (Result, error) {
	if p == nil || p.TenantID == "" {
		return Result{}, ErrNoTenant
	}
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	start := time.Now()
	res := Result{Tenant: p.TenantID}
	for _, d := range allDomains {
		permission := permissionFor(d)
		allowed, err := e.authorized(ctx, p, permission)
		if err != nil {
			return Result{}, fmt.Errorf("ai: authorize %s: %w", permission, err)
		}
		if !allowed {
			continue // RBAC or ABAC: skip domains the caller cannot read
		}
		rows, err := e.dispatch(ctx, p.TenantID, Query{Domain: d, Selector: subject, Range: r, Limit: e.maxRows}, e.maxRows)
		if err != nil {
			if errors.Is(err, ErrNoSource) {
				continue // domain not configured in this deployment
			}
			return Result{}, err
		}
		for _, row := range rows {
			// AIRCA-002: reduce each raw row to the per-domain allow-list
			// (U-092) before it leaves the engine — a correlation must not
			// egress a key the answer path would have stripped.
			clean := sanitizeRowFields(d, row)
			clean["_domain"] = string(d)
			res.Rows = append(res.Rows, clean)
		}
		if len(rows) > 0 {
			res.Domains = append(res.Domains, d)
		}
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

func (e *Engine) authorized(ctx context.Context, p *auth.Principal, permission string) (bool, error) {
	if !p.Has(permission) {
		return false, nil
	}
	if e.permissionAuthorize == nil {
		return true, nil
	}
	return e.permissionAuthorize(ctx, p, permission)
}

func (e *Engine) dispatch(ctx context.Context, tenant string, q Query, limit int) ([]Row, error) {
	switch q.Domain {
	case DomainMetrics:
		if e.metrics == nil {
			return nil, ErrNoSource
		}
		return e.metrics.QueryMetrics(ctx, tenant, q.Selector, q.Range, limit)
	case DomainEvents:
		if e.events == nil {
			return nil, ErrNoSource
		}
		return e.events.QueryEvents(ctx, tenant, q.Selector, q.Range, limit)
	case DomainEntities:
		if e.entities == nil {
			return nil, ErrNoSource
		}
		return e.entities.QueryEntities(ctx, tenant, q.Selector, limit)
	case DomainTopology:
		if e.topology == nil {
			return nil, ErrNoSource
		}
		return e.topology.QueryTopology(ctx, tenant, q)
	default:
		return nil, ErrUnknownDomain
	}
}

func (e *Engine) capLimit(limit int) int {
	if limit <= 0 || limit > e.maxRows {
		return e.maxRows
	}
	return limit
}
