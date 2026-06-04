package perf

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// PooledConfig describes the mixed-tenant query load for a pooled run.
type PooledConfig struct {
	QueryReps   int // tenant-scoped queries to run per tenant
	Concurrency int // concurrent workers (interleaving tenants = "mixed load")
}

// PooledOps are the store-specific hooks the pooled driver calls. Keeping them as
// closures decouples the harness from any particular table, so S48 and the
// fairness work (S-T7) reuse the driver for other tenant-owned stores.
type PooledOps struct {
	// CountRows runs one tenant-scoped query and returns the number of rows the
	// tenant can see. The implementation MUST enter the tenant boundary (RLS), so
	// the count doubles as an isolation assertion: it must equal the rows that
	// tenant owns — never another tenant's.
	CountRows func(ctx context.Context, tenant tenancy.ID) (int, error)
}

// PooledReport is the outcome of a DrivePooled run.
type PooledReport struct {
	Tenants           int
	ExpectedPerTenant int
	Queries           int
	IsolationOK       bool // every query saw exactly ExpectedPerTenant rows
	Mismatches        int  // queries that saw the wrong count (cross-tenant bleed or loss)
	Elapsed           time.Duration
	QueryThroughput   float64 // queries/sec
	Latency           LatencyStat
}

// String renders the report for logs and the baseline doc.
func (r PooledReport) String() string {
	return fmt.Sprintf(
		"pooled: tenants=%d rows/tenant=%d → %d scoped queries in %s = %.0f q/s; isolation_ok=%t mismatches=%d; latency[%s]",
		r.Tenants, r.ExpectedPerTenant, r.Queries, round(r.Elapsed), r.QueryThroughput,
		r.IsolationOK, r.Mismatches, r.Latency)
}

// DrivePooled runs tenant-scoped queries concurrently across many tenants sharing
// the pooled stores, measuring query latency under mixed-tenant load and
// asserting isolation: every query must see exactly expectedPerTenant rows (a
// cross-tenant leak would inflate the count; a scoping bug would deflate it).
func DrivePooled(ctx context.Context, tenants []tenancy.ID, expectedPerTenant int, ops PooledOps, cfg PooledConfig) (PooledReport, error) {
	if ops.CountRows == nil {
		return PooledReport{}, fmt.Errorf("perf: PooledOps.CountRows is required")
	}
	if cfg.QueryReps <= 0 {
		cfg.QueryReps = 1
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1
	}
	if len(tenants) == 0 {
		return PooledReport{}, fmt.Errorf("perf: no tenants to query")
	}

	// Build the job list: each tenant queried QueryReps times, interleaved so
	// workers hit different tenants concurrently (mixed-tenant load).
	type job struct{ tenant tenancy.ID }
	jobs := make([]job, 0, len(tenants)*cfg.QueryReps)
	for rep := 0; rep < cfg.QueryReps; rep++ {
		for _, t := range tenants {
			jobs = append(jobs, job{tenant: t})
		}
	}

	var (
		lat        Latencies
		mismatches atomic.Int64
		firstErr   atomic.Value
		next       atomic.Int64
	)
	start := time.Now()

	var wg sync.WaitGroup
	for c := 0; c < cfg.Concurrency; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(jobs) {
					return
				}
				if firstErr.Load() != nil {
					return
				}
				j := jobs[i]
				t0 := time.Now()
				got, err := ops.CountRows(ctx, j.tenant)
				lat.Record(time.Since(t0))
				if err != nil {
					firstErr.CompareAndSwap(nil, err)
					return
				}
				if got != expectedPerTenant {
					mismatches.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	if e := firstErr.Load(); e != nil {
		return PooledReport{}, e.(error)
	}

	rep := PooledReport{
		Tenants:           len(tenants),
		ExpectedPerTenant: expectedPerTenant,
		Queries:           len(jobs),
		Mismatches:        int(mismatches.Load()),
		IsolationOK:       mismatches.Load() == 0,
		Elapsed:           elapsed,
		Latency:           lat.Summary(),
	}
	if elapsed > 0 {
		rep.QueryThroughput = float64(len(jobs)) / elapsed.Seconds()
	}
	return rep, nil
}
