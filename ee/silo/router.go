// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package silo

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// Router implements tenancy.Router over the tenant registry: it resolves
// every tenant's isolation targets from the tenants table (read as the
// least-privilege provider role), cached briefly. It FAILS CLOSED: if the
// registry cannot be read and the cache has expired, routing returns an
// error — a siloed tenant is never silently degraded to the pooled stores
// (the S-T2 watch-out).
type Router struct {
	pool   *pgxpool.Pool
	planes map[string]DataPlane
	ttl    time.Duration

	// Seams for tests; production uses time.Now + the registry query.
	now   func() time.Time
	fetch func(ctx context.Context) (map[string]registryRow, error)

	mu          sync.Mutex
	byID        map[string]registryRow
	fetched     time.Time
	staleServes uint64
	lastErr     string
}

// RouterStats reports the router's degradation counters (U-090): how often a
// stale snapshot was served on registry errors, and the last such error.
type RouterStats struct {
	StaleServes uint64
	LastError   string
	SnapshotAge time.Duration
}

// Stats returns the current degradation counters.
func (r *Router) Stats() RouterStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := RouterStats{StaleServes: r.staleServes, LastError: r.lastErr}
	if !r.fetched.IsZero() {
		st.SnapshotAge = r.now().Sub(r.fetched)
	}
	return st
}

type registryRow struct {
	slug      string
	status    string
	model     tenancy.IsolationModel
	residency string
}

// NewRouter builds the registry-backed isolation router.
func NewRouter(pool *pgxpool.Pool, planes map[string]DataPlane, ttl time.Duration) *Router {
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	if planes == nil {
		planes = map[string]DataPlane{}
	}
	r := &Router{pool: pool, planes: planes, ttl: ttl, byID: map[string]registryRow{}, now: time.Now}
	r.fetch = r.fetchRegistry
	return r
}

// Invalidate drops the cache (called after lifecycle changes so a freshly
// siloed tenant routes correctly without waiting out the TTL).
func (r *Router) Invalidate() {
	r.mu.Lock()
	r.fetched = time.Time{}
	r.mu.Unlock()
}

// load refreshes the registry snapshot if stale. Serving a stale-but-known
// snapshot on a read ERROR is tolerated for at most ONE extra TTL (U-090) —
// and is surfaced loudly (warn log + Stats counter) every time it happens.
// Beyond that the router refuses to answer (fail closed) rather than route
// on ancient state: a siloed tenant must never ride an outdated registry.
func (r *Router) load(ctx context.Context) (map[string]registryRow, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.now().Sub(r.fetched) < r.ttl {
		return r.byID, nil
	}
	fresh, err := r.fetch(ctx)
	if err != nil {
		age := r.now().Sub(r.fetched)
		r.lastErr = err.Error()
		if !r.fetched.IsZero() && age < 2*r.ttl {
			// Brief registry blip: serve the known snapshot, but say so.
			r.staleServes++
			slog.Warn("silo: tenant registry unavailable — serving STALE snapshot (U-090)",
				"age", age, "stale_cap", 2*r.ttl, "error", err)
			return r.byID, nil
		}
		return nil, fmt.Errorf("silo: tenant registry unavailable and the cached snapshot is too old to trust (age %s > stale cap %s): %w",
			age, 2*r.ttl, err)
	}
	r.byID, r.fetched, r.lastErr = fresh, r.now(), ""
	return r.byID, nil
}

// fetchRegistry reads the tenant registry as the least-privilege provider role.
func (r *Router) fetchRegistry(ctx context.Context) (map[string]registryRow, error) {
	fresh := map[string]registryRow{}
	err := tenancy.InProvider(ctx, r.pool, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(ctx, `SELECT id::text, slug, status, isolation_model, residency FROM tenants`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var row registryRow
			var model string
			if err := rows.Scan(&id, &row.slug, &row.status, &model, &row.residency); err != nil {
				return err
			}
			row.model = tenancy.IsolationModel(model)
			fresh[id] = row
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return fresh, nil
}

// TargetsFor resolves one tenant's isolation targets.
func (r *Router) TargetsFor(ctx context.Context, tenantID string) (tenancy.Targets, error) {
	reg, err := r.load(ctx)
	if err != nil {
		return tenancy.Targets{}, err
	}
	row, ok := reg[tenantID]
	if !ok {
		// Unknown to the registry = pooled (the default tenant in dev, or a
		// tenant created outside the provider plane). Pooled is not a silo
		// downgrade here: the tenant never had isolated stores.
		return tenancy.Targets{Model: tenancy.IsolationPooled}, nil
	}
	t := tenancy.Targets{Model: row.model, Residency: row.residency}
	switch row.model {
	case tenancy.IsolationSiloed:
		t.PGSchema = SchemaName(tenantID)
		t.CHDatabase = CHDatabase(tenantID)
		t.BusNamespace = BusNamespace(row.slug)
		t.ObjectPrefix = ObjectPrefix(tenantID)
	case tenancy.IsolationHybrid:
		t.CHDatabase = CHDatabase(tenantID)
		t.BusNamespace = BusNamespace(row.slug)
		t.ObjectPrefix = ObjectPrefix(tenantID)
	default:
		return tenancy.Targets{Model: tenancy.IsolationPooled, Residency: row.residency}, nil
	}
	if plane, ok := r.planes[row.residency]; ok {
		t.CHBaseURL = plane.CHURL
	}
	return t, nil
}

// BusNamespaceTenants maps every active siloed/hybrid tenant's bus namespace
// to its tenant id (TENANT-101: the lane is the consumer's authoritative
// tenant source for agent-published planes).
func (r *Router) BusNamespaceTenants(ctx context.Context) (map[string]string, error) {
	reg, err := r.load(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for id, row := range reg {
		if row.model != tenancy.IsolationSiloed && row.model != tenancy.IsolationHybrid {
			continue
		}
		if row.status == "offboarding" || row.status == "deleted" {
			continue
		}
		out[BusNamespace(row.slug)] = id
	}
	return out, nil
}

// BusNamespaces lists the namespaced lanes of every non-offboarded siloed or
// hybrid tenant (consumer fan-out at startup).
func (r *Router) BusNamespaces(ctx context.Context) ([]string, error) {
	reg, err := r.load(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, row := range reg {
		if row.model != tenancy.IsolationSiloed && row.model != tenancy.IsolationHybrid {
			continue
		}
		if row.status == "offboarding" || row.status == "deleted" {
			continue
		}
		out = append(out, BusNamespace(row.slug))
	}
	return out, nil
}
