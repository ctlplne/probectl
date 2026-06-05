package fairness

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// PGStore persists per-tenant fairness policies (tenant_fairness, migration
// 0031). Reads run via the provider role — policy is platform-protection
// state the gate consults for EVERY tenant; writes happen from the provider
// plane (ee) through Upsert. The table is on the silo deny list (provider
// vocabulary, never copied into tenant schemas).
type PGStore struct{ pool *pgxpool.Pool }

// NewPGStore wraps a pool.
func NewPGStore(pool *pgxpool.Pool) *PGStore { return &PGStore{pool: pool} }

const policyCols = `coalesce(results_per_sec, 0), coalesce(flow_events_per_sec, 0),
	coalesce(ingest_bytes_per_sec, 0), coalesce(burst_seconds, 0),
	coalesce(query_concurrency, 0), coalesce(queries_per_min, 0), coalesce(weight, 0)`

func scanPolicy(row pgx.Row) (Policy, error) {
	var p Policy
	err := row.Scan(&p.ResultsPerSec, &p.FlowEventsPerSec, &p.IngestBytesPerSec,
		&p.BurstSeconds, &p.QueryConcurrency, &p.QueriesPerMin, &p.Weight)
	return p, err
}

// PolicyFor implements PolicySource. ok=false = no override row.
func (s *PGStore) PolicyFor(ctx context.Context, tenantID string) (Policy, bool, error) {
	var p Policy
	found := false
	err := tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		got, err := scanPolicy(q.QueryRow(ctx,
			`SELECT `+policyCols+` FROM tenant_fairness WHERE tenant_id = $1`, tenantID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		p, found = got, true
		return nil
	})
	return p, found, err
}

// Upsert stores a tenant's policy override (the provider tuning surface).
func (s *PGStore) Upsert(ctx context.Context, tenantID string, p Policy, by string) error {
	return tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		_, err := q.Exec(ctx, `
			INSERT INTO tenant_fairness (tenant_id, results_per_sec, flow_events_per_sec,
				ingest_bytes_per_sec, burst_seconds, query_concurrency, queries_per_min,
				weight, updated_at, updated_by)
			VALUES ($1, nullif($2, 0), nullif($3, 0), nullif($4, 0), nullif($5, 0),
				nullif($6, 0), nullif($7, 0), nullif($8, 0), $9, $10)
			ON CONFLICT (tenant_id) DO UPDATE SET
				results_per_sec = excluded.results_per_sec,
				flow_events_per_sec = excluded.flow_events_per_sec,
				ingest_bytes_per_sec = excluded.ingest_bytes_per_sec,
				burst_seconds = excluded.burst_seconds,
				query_concurrency = excluded.query_concurrency,
				queries_per_min = excluded.queries_per_min,
				weight = excluded.weight,
				updated_at = excluded.updated_at,
				updated_by = excluded.updated_by`,
			tenantID, p.ResultsPerSec, p.FlowEventsPerSec, p.IngestBytesPerSec,
			p.BurstSeconds, p.QueryConcurrency, p.QueriesPerMin, p.Weight,
			time.Now().UTC(), by)
		return err
	})
}

// All returns every stored override keyed by tenant ID (the provider view).
func (s *PGStore) All(ctx context.Context) (map[string]Policy, error) {
	out := map[string]Policy{}
	err := tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(ctx, `SELECT tenant_id::text, `+policyCols+` FROM tenant_fairness`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var p Policy
			if err := rows.Scan(&id, &p.ResultsPerSec, &p.FlowEventsPerSec, &p.IngestBytesPerSec,
				&p.BurstSeconds, &p.QueryConcurrency, &p.QueriesPerMin, &p.Weight); err != nil {
				return err
			}
			out[id] = p
		}
		return rows.Err()
	})
	return out, err
}
