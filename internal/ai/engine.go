package ai

import (
	"context"
	"errors"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
)

// Engine errors.
var (
	ErrNoTenant      = errors.New("ai: no tenant on principal (fail closed)")
	ErrForbidden     = errors.New("ai: forbidden — insufficient permission")
	ErrUnknownDomain = errors.New("ai: unknown query domain")
	ErrNoSource      = errors.New("ai: no source configured for domain")
)

// Engine is probectl's unified semantic query layer — THE tenant-then-RBAC security
// boundary for the API, the AI/RCA layer (S24), and the MCP server (S25). It takes
// the tenant from the authenticated principal (never the query), enforces RBAC,
// applies cost/timeout guards, and dispatches to the store sources, returning a
// normalized envelope with provenance.
type Engine struct {
	metrics  MetricsSource
	events   EventsSource
	entities EntitiesSource
	topology TopologySource

	maxRows int
	timeout time.Duration
}

// Option configures an Engine.
type Option func(*Engine)

// WithMetrics / WithEvents / WithEntities / WithTopology register store sources.
func WithMetrics(s MetricsSource) Option   { return func(e *Engine) { e.metrics = s } }
func WithEvents(s EventsSource) Option     { return func(e *Engine) { e.events = s } }
func WithEntities(s EntitiesSource) Option { return func(e *Engine) { e.entities = s } }
func WithTopology(s TopologySource) Option { return func(e *Engine) { e.topology = s } }

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

// Query runs a single-domain query under the principal's tenant and RBAC. The
// tenant boundary is enforced FIRST (from the principal, never the query), then
// RBAC; both fail closed.
func (e *Engine) Query(ctx context.Context, p *auth.Principal, q Query) (Result, error) {
	if p == nil || p.TenantID == "" {
		return Result{}, ErrNoTenant
	}
	perm := permissionFor(q.Domain)
	if perm == "" {
		return Result{}, ErrUnknownDomain
	}
	if !p.Has(perm) {
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

// Correlate fans a subject across every domain the principal may read and returns
// one envelope with per-domain provenance — the cross-store join. Domains the
// caller cannot read are silently skipped, so a correlation never leaks
// out-of-scope data.
func (e *Engine) Correlate(ctx context.Context, p *auth.Principal, subject map[string]string, r TimeRange) (Result, error) {
	if p == nil || p.TenantID == "" {
		return Result{}, ErrNoTenant
	}
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	start := time.Now()
	res := Result{Tenant: p.TenantID}
	for _, d := range allDomains {
		if !p.Has(permissionFor(d)) {
			continue // RBAC: skip domains the caller cannot read
		}
		rows, err := e.dispatch(ctx, p.TenantID, Query{Domain: d, Selector: subject, Range: r, Limit: e.maxRows}, e.maxRows)
		if err != nil {
			if errors.Is(err, ErrNoSource) {
				continue // domain not configured in this deployment
			}
			return Result{}, err
		}
		for _, row := range rows {
			row["_domain"] = string(d)
			res.Rows = append(res.Rows, row)
		}
		if len(rows) > 0 {
			res.Domains = append(res.Domains, d)
		}
	}
	res.Elapsed = time.Since(start)
	return res, nil
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
