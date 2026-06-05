// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

//go:build integration

package billing

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/usage"
	"github.com/imfeelingtheagi/probectl/migrations"
)

// Live-Postgres round-trip for the metering store: counters add (UPSERT),
// gauges snapshot, quotas CRUD — all as the probectl_provider role through
// the explicit provider_metering policy — and the per-tenant counter counts
// INSIDE the tenant's own scope (reconciliation against the source of truth).
func itPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("PROBECTL_TEST_POSTGRES")
	if dsn == "" {
		dsn = "postgres://probectl:probectl@localhost:5432/probectl"
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

func TestPGMeteringRoundTrip(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()

	var tenantID string
	slug := "it-meter-" + time.Now().UTC().Format("150405")
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (slug, name) VALUES ($1, $1) RETURNING id::text`, slug).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}

	st := NewPGStore(pool)
	period := PeriodStart(time.Now())

	// Counters accumulate across flushes.
	for i := 0; i < 2; i++ {
		if err := st.AddCounters(ctx, []CounterDelta{
			{TenantID: tenantID, Meter: usage.MeterResultsIngested, Period: period, Delta: 21},
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Gauges overwrite within the period.
	if err := st.SetGauge(ctx, tenantID, usage.MeterAgents, period, 9); err != nil {
		t.Fatal(err)
	}
	if err := st.SetGauge(ctx, tenantID, usage.MeterAgents, period, 4); err != nil {
		t.Fatal(err)
	}

	recs, err := st.Query(ctx, period.Add(-time.Hour), period.Add(time.Hour), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, r := range recs {
		got[r.Meter] = r.Value
		if r.TenantSlug != slug {
			t.Fatalf("slug join: %+v", r)
		}
	}
	if got[usage.MeterResultsIngested] != 42 || got[usage.MeterAgents] != 4 {
		t.Fatalf("round-trip values: %+v", got)
	}

	// Quotas CRUD.
	five := 5
	if err := st.SetQuota(ctx, Quota{TenantID: tenantID, MaxAgents: &five, UpdatedBy: "it"}); err != nil {
		t.Fatal(err)
	}
	q, err := st.QuotaFor(ctx, tenantID)
	if err != nil || q.MaxAgents == nil || *q.MaxAgents != 5 || q.MaxTests != nil {
		t.Fatalf("quota round-trip: %+v %v", q, err)
	}

	// The per-tenant counter reconciles against the live tables, inside the
	// tenant's own scope (zero of each for a fresh tenant).
	agents, tests, err := PGTenantCounter(pool)(ctx, tenantID)
	if err != nil || agents != 0 || tests != 0 {
		t.Fatalf("tenant counter: %d %d %v", agents, tests, err)
	}
	// The lister sees the tenant.
	ids, err := PGTenantLister(pool)(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, id := range ids {
		if id == tenantID {
			found = true
		}
	}
	if !found {
		t.Fatal("lister must include the new tenant")
	}
}
