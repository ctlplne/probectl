// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package billing

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/usage"
)

// The gauge collector snapshots per-tenant resource counts (agents, tests)
// on a cadence. The key design property (the S-T3 watch-outs): counts are
// taken INSIDE each tenant's own scope via tenancy.InTenant — RLS-bound and
// silo-routed — so there is no cross-tenant read path at all, the counts ARE
// the source of truth (reconciliation by construction), and a siloed
// tenant's resources are counted exactly once, in its own schema.

// TenantLister lists active tenants (the provider role's registry read).
type TenantLister func(ctx context.Context) ([]string, error)

// TenantCounter counts one tenant's resources within its own scope.
type TenantCounter func(ctx context.Context, tenantID string) (agents, tests int64, err error)

// Collector runs the snapshots.
type Collector struct {
	store   Store
	tenants TenantLister
	count   TenantCounter
	log     *slog.Logger
	now     func() time.Time
}

// NewCollector wires a collector.
func NewCollector(store Store, tenants TenantLister, count TenantCounter, log *slog.Logger) *Collector {
	if log == nil {
		log = slog.Default()
	}
	return &Collector{store: store, tenants: tenants, count: count, log: log, now: time.Now}
}

// WithClock overrides time (tests).
func (c *Collector) WithClock(now func() time.Time) *Collector {
	c.now = now
	return c
}

// Snapshot counts every active tenant once and upserts the gauges for the
// current period. Per-tenant failures are logged and skipped (one tenant's
// trouble must not blank every tenant's gauges).
func (c *Collector) Snapshot(ctx context.Context) error {
	ids, err := c.tenants(ctx)
	if err != nil {
		return err
	}
	period := PeriodStart(c.now())
	for _, id := range ids {
		agents, tests, err := c.count(ctx, id)
		if err != nil {
			c.log.Warn("metering: tenant snapshot failed", "tenant", id, "error", err.Error())
			continue
		}
		if err := c.store.SetGauge(ctx, id, usage.MeterAgents, period, agents); err != nil {
			return err
		}
		if err := c.store.SetGauge(ctx, id, usage.MeterTests, period, tests); err != nil {
			return err
		}
	}
	return nil
}

// Run snapshots on the interval until ctx ends (one immediate snapshot
// first, so gauges exist right after startup).
func (c *Collector) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	if err := c.Snapshot(ctx); err != nil {
		c.log.Warn("metering: initial snapshot failed", "error", err.Error())
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.Snapshot(ctx); err != nil {
				c.log.Warn("metering: snapshot failed", "error", err.Error())
			}
		}
	}
}

// PGTenantLister lists active/suspended tenants as the provider role.
func PGTenantLister(pool *pgxpool.Pool) TenantLister {
	return func(ctx context.Context) ([]string, error) {
		var ids []string
		err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
			rows, err := q.Query(ctx,
				`SELECT id::text FROM tenants WHERE status IN ('active','suspended')`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return err
				}
				ids = append(ids, id)
			}
			return rows.Err()
		})
		return ids, err
	}
}

// PGTenantCounter counts agents + tests inside the tenant's own scope
// (RLS-bound, silo-routed — InTenant routes a siloed tenant to its schema).
func PGTenantCounter(pool *pgxpool.Pool) TenantCounter {
	return func(ctx context.Context, tenantID string) (int64, int64, error) {
		var agents, tests int64
		tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
		err := tenancy.InTenant(tctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM agents`).Scan(&agents); err != nil {
				return err
			}
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM tests`).Scan(&tests)
		})
		return agents, tests, err
	}
}
