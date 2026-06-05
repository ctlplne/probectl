// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package silo

import (
	"context"
	"fmt"
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

	mu      sync.Mutex
	byID    map[string]registryRow
	fetched time.Time
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
	return &Router{pool: pool, planes: planes, ttl: ttl, byID: map[string]registryRow{}}
}

// Invalidate drops the cache (called after lifecycle changes so a freshly
// siloed tenant routes correctly without waiting out the TTL).
func (r *Router) Invalidate() {
	r.mu.Lock()
	r.fetched = time.Time{}
	r.mu.Unlock()
}

// load refreshes the registry snapshot if stale. Serving a stale-but-known
// snapshot on a read ERROR is allowed only within 10× TTL — beyond that the
// router refuses to answer (fail closed) rather than route on ancient state.
func (r *Router) load(ctx context.Context) (map[string]registryRow, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.fetched) < r.ttl {
		return r.byID, nil
	}
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
		if !r.fetched.IsZero() && time.Since(r.fetched) < 10*r.ttl {
			return r.byID, nil // brief registry blip: serve the known snapshot
		}
		return nil, fmt.Errorf("silo: tenant registry unavailable: %w", err)
	}
	r.byID, r.fetched = fresh, time.Now()
	return r.byID, nil
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
