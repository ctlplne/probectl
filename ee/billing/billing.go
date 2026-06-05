// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).
// See ee/doc.go for the boundary rules every ee/ file observes.

// Package billing is per-tenant metering, usage and billing export (S-T3,
// F53), unlocked by the metering license feature. It meters the tenant-tagged
// streams ALREADY flowing (results, flow batches, AI calls — via the core
// internal/usage seam) plus periodic snapshots (agents, tests — counted
// per-tenant INSIDE each tenant's own scope, so there is no cross-tenant read
// path and pooled/siloed tenants are counted identically, never doubly).
//
// It deliberately does NOT build an invoicing engine: usage exports to the
// MSP's existing billing/PSA system as documented CSV / JSON-Lines (the
// ratified first export target — generic, vendor-neutral).
package billing

import (
	"context"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/usage"
)

// Meter kinds.
const (
	KindCounter = "counter" // monotonic within a period (summed on rollup)
	KindGauge   = "gauge"   // point-in-time snapshot (peak on rollup)
)

// MeterKind classifies a meter name.
func MeterKind(meter string) string {
	switch meter {
	case usage.MeterAgents, usage.MeterTests:
		return KindGauge
	default:
		return KindCounter
	}
}

// MeterUnit is the export unit for a meter.
func MeterUnit(meter string) string {
	if meter == usage.MeterIngestBytes {
		return "bytes"
	}
	return "count"
}

// Meters is the canonical meter set (export completeness + console order).
func Meters() []string {
	return []string{
		usage.MeterAgents, usage.MeterTests,
		usage.MeterResultsIngested, usage.MeterIngestBytes,
		usage.MeterFlowEvents, usage.MeterAICalls,
	}
}

// Period is the metering bucket: hourly, UTC. Hour granularity keeps records
// small enough to query for months while letting day/month rollups stay exact.
const Period = time.Hour

// PeriodStart truncates t to its bucket.
func PeriodStart(t time.Time) time.Time { return t.UTC().Truncate(Period) }

// UsageRecord is one aggregated usage row — the MeteringRecord contract.
type UsageRecord struct {
	TenantID    string    `json:"tenant_id"`
	TenantSlug  string    `json:"tenant_slug"`
	Meter       string    `json:"meter"`
	Kind        string    `json:"kind"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Value       int64     `json:"value"`
	Unit        string    `json:"unit"`
}

// Quota is a tenant's creation limits. nil fields = unlimited.
type Quota struct {
	TenantID  string `json:"tenant_id"`
	MaxAgents *int   `json:"max_agents"`
	MaxTests  *int   `json:"max_tests"`
	UpdatedBy string `json:"updated_by,omitempty"`
}

// Store persists usage records and quotas.
type Store interface {
	// AddCounters adds deltas into (tenant, meter, period) counter rows.
	AddCounters(ctx context.Context, deltas []CounterDelta) error
	// SetGauge upserts a gauge snapshot for (tenant, meter, period).
	SetGauge(ctx context.Context, tenantID, meter string, period time.Time, value int64) error
	// Query returns records overlapping [from, to), optionally one tenant.
	Query(ctx context.Context, from, to time.Time, tenantID string) ([]UsageRecord, error)
	// QuotaFor returns the tenant's quota (zero-value = unlimited).
	QuotaFor(ctx context.Context, tenantID string) (Quota, error)
	// SetQuota upserts a tenant's quota.
	SetQuota(ctx context.Context, q Quota) error
}

// CounterDelta is one flush increment.
type CounterDelta struct {
	TenantID string
	Meter    string
	Period   time.Time
	Delta    int64
}

// Rollup granularities for queries/exports.
const (
	RollupHour = "hour" // as stored
	RollupDay  = "day"  // counters summed, gauges peak
)

// Rollup aggregates hourly records to the requested granularity. Counters
// SUM (exact — hourly buckets partition the day); gauges take the PEAK
// (the fair billing snapshot for capacity-shaped meters).
func Rollup(records []UsageRecord, granularity string) []UsageRecord {
	if granularity != RollupDay {
		return records
	}
	type key struct {
		tenant, meter string
		day           time.Time
	}
	agg := map[key]*UsageRecord{}
	var order []key
	for _, r := range records {
		day := r.PeriodStart.UTC().Truncate(24 * time.Hour)
		k := key{r.TenantID, r.Meter, day}
		cur, ok := agg[k]
		if !ok {
			cp := r
			cp.PeriodStart, cp.PeriodEnd = day, day.Add(24*time.Hour)
			agg[k] = &cp
			order = append(order, k)
			continue
		}
		if r.Kind == KindGauge {
			if r.Value > cur.Value {
				cur.Value = r.Value
			}
		} else {
			cur.Value += r.Value
		}
	}
	out := make([]UsageRecord, 0, len(order))
	for _, k := range order {
		out = append(out, *agg[k])
	}
	return out
}
