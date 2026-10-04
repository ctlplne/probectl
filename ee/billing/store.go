// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package billing

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// PGStore persists usage/quotas via the probectl_provider role (the explicit
// provider_metering policy from migration 0026): billing data about tenants
// is provider-plane data — written by the recorder/collector, read for
// showback/export. The role's reach stays bounded at the storage layer.
type PGStore struct{ pool *pgxpool.Pool }

// NewPGStore wraps a pool.
func NewPGStore(pool *pgxpool.Pool) *PGStore { return &PGStore{pool: pool} }

func (s *PGStore) in(ctx context.Context, fn func(context.Context, tenancy.Querier) error) error {
	return tenancy.InProvider(ctx, s.pool, fn)
}

// AddCounters adds deltas with one UPSERT per row (rows are few: tenants ×
// meters per hour), all in ONE transaction, so the batch lands or it does not.
// AUD-21: a batch carrying an idempotency key (BatchID) first claims that key
// in usage_flush_batches IN THE SAME TRANSACTION; if the row already exists the
// batch landed on an earlier attempt (a commit the recorder only saw fail), so
// the whole call is a no-op — the counters are never applied twice. An empty
// key keeps the plain additive behavior for direct callers and backfills.
func (s *PGStore) AddCounters(ctx context.Context, deltas []CounterDelta) error {
	if len(deltas) == 0 {
		return nil
	}
	return s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		if id := batchIDOf(deltas); id != "" {
			tag, err := q.Exec(ctx,
				`INSERT INTO usage_flush_batches (batch_id) VALUES ($1) ON CONFLICT (batch_id) DO NOTHING`, id)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return nil // this batch already landed durably — idempotent no-op
			}
			// Opportunistic prune: a batch id is only needed while its retries
			// are in flight (seconds to minutes); keep two days and bound growth.
			if _, err := q.Exec(ctx,
				`DELETE FROM usage_flush_batches WHERE applied_at < now() - interval '2 days'`); err != nil {
				return err
			}
		}
		for _, d := range deltas {
			if _, err := q.Exec(ctx, `
				INSERT INTO usage_records (tenant_id, meter, kind, period_start, period_end, value)
				VALUES ($1, $2, 'counter', $3, $4, $5)
				ON CONFLICT (tenant_id, meter, period_start)
				DO UPDATE SET value = usage_records.value + EXCLUDED.value, updated_at = now()`,
				d.TenantID, d.Meter, d.Period, d.Period.Add(Period), d.Delta); err != nil {
				return err
			}
		}
		return nil
	})
}

// SetGauge upserts a snapshot (latest snapshot in a period wins).
func (s *PGStore) SetGauge(ctx context.Context, tenantID, meter string, period time.Time, value int64) error {
	return s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		_, err := q.Exec(ctx, `
			INSERT INTO usage_records (tenant_id, meter, kind, period_start, period_end, value)
			VALUES ($1, $2, 'gauge', $3, $4, $5)
			ON CONFLICT (tenant_id, meter, period_start)
			DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
			tenantID, meter, period, period.Add(Period), value)
		return err
	})
}

// Query returns records overlapping [from, to), slug-joined, ordered.
func (s *PGStore) Query(ctx context.Context, from, to time.Time, tenantID string) ([]UsageRecord, error) {
	var out []UsageRecord
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		sql := `
			SELECT u.tenant_id::text, t.slug, u.meter, u.kind, u.period_start, u.period_end, u.value
			  FROM usage_records u JOIN tenants t ON t.id = u.tenant_id
			 WHERE u.period_start >= $1 AND u.period_start < $2`
		args := []any{from, to}
		if tenantID != "" {
			sql += ` AND u.tenant_id = $3`
			args = append(args, tenantID)
		}
		sql += ` ORDER BY t.slug, u.meter, u.period_start`
		rows, err := q.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r UsageRecord
			if err := rows.Scan(&r.TenantID, &r.TenantSlug, &r.Meter, &r.Kind, &r.PeriodStart, &r.PeriodEnd, &r.Value); err != nil {
				return err
			}
			r.Unit = MeterUnit(r.Meter)
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// QuotaFor returns the tenant's quota (zero-value = unlimited).
func (s *PGStore) QuotaFor(ctx context.Context, tenantID string) (Quota, error) {
	q := Quota{TenantID: tenantID}
	err := s.in(ctx, func(ctx context.Context, qr tenancy.Querier) error {
		rows, err := qr.Query(ctx,
			`SELECT max_agents, max_tests, updated_by FROM tenant_quotas WHERE tenant_id = $1`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			if err := rows.Scan(&q.MaxAgents, &q.MaxTests, &q.UpdatedBy); err != nil {
				return err
			}
		}
		return rows.Err()
	})
	return q, err
}

// SetQuota upserts a tenant's quota.
func (s *PGStore) SetQuota(ctx context.Context, quota Quota) error {
	return s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		_, err := q.Exec(ctx, `
			INSERT INTO tenant_quotas (tenant_id, max_agents, max_tests, updated_by, updated_at)
			VALUES ($1, $2, $3, $4, now())
			ON CONFLICT (tenant_id)
			DO UPDATE SET max_agents = EXCLUDED.max_agents, max_tests = EXCLUDED.max_tests,
			              updated_by = EXCLUDED.updated_by, updated_at = now()`,
			quota.TenantID, quota.MaxAgents, quota.MaxTests, quota.UpdatedBy)
		return err
	})
}

// --- In-memory implementation (unit tests) ---

// MemStore is a thread-safe in-memory Store. Slugs render as the tenant ID.
type MemStore struct {
	mu      sync.Mutex
	records map[counterKey]*UsageRecord
	quotas  map[string]Quota
	slugs   map[string]string
	applied map[string]bool // batch ids already applied (AUD-21 idempotency)
	failAdd bool            // tests: force one AddCounters failure
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{records: map[counterKey]*UsageRecord{}, quotas: map[string]Quota{}, slugs: map[string]string{}, applied: map[string]bool{}}
}

// SetSlug names a tenant (export tests).
func (m *MemStore) SetSlug(id, slug string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.slugs[id] = slug
}

// failNextAdd makes the next AddCounters fail (lossless-flush tests).
func (m *MemStore) failNextAdd() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failAdd = true
}

func (m *MemStore) slug(id string) string {
	if s, ok := m.slugs[id]; ok {
		return s
	}
	return id
}

func (m *MemStore) AddCounters(_ context.Context, deltas []CounterDelta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failAdd {
		m.failAdd = false
		return context.DeadlineExceeded // pre-apply failure: nothing persisted
	}
	if id := batchIDOf(deltas); id != "" {
		if m.applied[id] {
			return nil // idempotent: this batch already landed durably
		}
		m.applied[id] = true
	}
	for _, d := range deltas {
		k := counterKey{tenant: d.TenantID, meter: d.Meter, period: d.Period}
		if r, ok := m.records[k]; ok {
			r.Value += d.Delta
			continue
		}
		m.records[k] = &UsageRecord{
			TenantID: d.TenantID, TenantSlug: m.slug(d.TenantID), Meter: d.Meter,
			Kind: KindCounter, PeriodStart: d.Period, PeriodEnd: d.Period.Add(Period),
			Value: d.Delta, Unit: MeterUnit(d.Meter),
		}
	}
	return nil
}

func (m *MemStore) SetGauge(_ context.Context, tenantID, meter string, period time.Time, value int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := counterKey{tenant: tenantID, meter: meter, period: period}
	m.records[k] = &UsageRecord{
		TenantID: tenantID, TenantSlug: m.slug(tenantID), Meter: meter,
		Kind: KindGauge, PeriodStart: period, PeriodEnd: period.Add(Period),
		Value: value, Unit: MeterUnit(meter),
	}
	return nil
}

func (m *MemStore) Query(_ context.Context, from, to time.Time, tenantID string) ([]UsageRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []UsageRecord
	for _, r := range m.records {
		if r.PeriodStart.Before(from) || !r.PeriodStart.Before(to) {
			continue
		}
		if tenantID != "" && r.TenantID != tenantID {
			continue
		}
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.TenantSlug != b.TenantSlug {
			return a.TenantSlug < b.TenantSlug
		}
		if a.Meter != b.Meter {
			return a.Meter < b.Meter
		}
		return a.PeriodStart.Before(b.PeriodStart)
	})
	return out, nil
}

func (m *MemStore) QuotaFor(_ context.Context, tenantID string) (Quota, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if q, ok := m.quotas[tenantID]; ok {
		return q, nil
	}
	return Quota{TenantID: tenantID}, nil
}

func (m *MemStore) SetQuota(_ context.Context, q Quota) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.quotas[q.TenantID] = q
	return nil
}
