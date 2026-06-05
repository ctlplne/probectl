package perf

// The multi-tenant NOISY-NEIGHBOR scenario (S48; PRD §5.4 / F57): one tenant
// floods the shared pooled path while a quiet tenant runs its ordinary
// workload. The gate asserts two things, in order of severity:
//
//  1. CORRECTNESS NEVER BENDS — every one of the quiet tenant's results
//     lands under its own tenant_id, complete and unmixed, no matter what
//     the neighbor does (guardrail 1 under load).
//  2. The quiet tenant's experience degrades boundedly: its publish p95
//     under a flooding neighbor stays within MaxNoisyInflation × its solo
//     p95 (no cross-tenant performance bleed).

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// NoisyConfig shapes the scenario.
type NoisyConfig struct {
	// QuietResults is the quiet tenant's workload size (both phases).
	QuietResults int
	// NoisyFactor multiplies the quiet workload for the flooding neighbor.
	NoisyFactor int
	// Producers is the concurrency for each tenant's publisher.
	Producers int
	// SettleTimeout bounds the post-publish drain wait per phase.
	SettleTimeout time.Duration
}

// NoisyReport is the scenario outcome.
type NoisyReport struct {
	Ran          bool
	SoloP95      time.Duration // quiet tenant alone
	NoisyP95     time.Duration // quiet tenant beside the flood
	Inflation    float64       // NoisyP95 / SoloP95
	QuietCorrect bool          // every quiet series landed, correctly scoped
	QuietSeries  int
	NoisySeries  int
}

// String renders the report for logs and docs.
func (r NoisyReport) String() string {
	return fmt.Sprintf("noisy-neighbor: solo p95 %s → under-noise p95 %s = %.2fx inflation; quiet correct=%t",
		round(r.SoloP95), round(r.NoisyP95), r.Inflation, r.QuietCorrect)
}

// DriveNoisyNeighbor runs the two phases on the lightweight in-process stack
// and reports the quiet tenant's experience.
func DriveNoisyNeighbor(ctx context.Context, cfg NoisyConfig) (NoisyReport, error) {
	if cfg.QuietResults <= 0 {
		cfg.QuietResults = 500
	}
	if cfg.NoisyFactor <= 0 {
		cfg.NoisyFactor = 10
	}
	if cfg.Producers <= 0 {
		cfg.Producers = 4
	}
	if cfg.SettleTimeout <= 0 {
		cfg.SettleTimeout = 60 * time.Second
	}

	// Phase 1 — solo: the quiet tenant alone.
	soloP95, _, soloOK, err := runPhase(ctx, cfg, false)
	if err != nil {
		return NoisyReport{}, fmt.Errorf("perf: solo phase: %w", err)
	}

	// Phase 2 — the same quiet workload beside a flooding neighbor.
	noisyP95, counts, noisyOK, err := runPhase(ctx, cfg, true)
	if err != nil {
		return NoisyReport{}, fmt.Errorf("perf: noisy phase: %w", err)
	}

	rep := NoisyReport{
		Ran:          true,
		SoloP95:      soloP95,
		NoisyP95:     noisyP95,
		QuietCorrect: soloOK && noisyOK,
		QuietSeries:  counts.quiet,
		NoisySeries:  counts.noisy,
	}
	floor := time.Microsecond
	base := soloP95
	if base < floor {
		base = floor
	}
	rep.Inflation = float64(noisyP95) / float64(base)
	if rep.Inflation < 1 {
		rep.Inflation = 1 // contention can only be ≥ solo; clamp jitter
	}
	return rep, nil
}

type phaseCounts struct{ quiet, noisy int }

// runPhase publishes the quiet tenant's workload (and, when withNoise, the
// neighbor's flood concurrently), waits for the drain, and verifies the
// quiet tenant's series count + scoping.
func runPhase(ctx context.Context, cfg NoisyConfig, withNoise bool) (quietP95 time.Duration, counts phaseCounts, quietCorrect bool, err error) {
	b := bus.NewMemory()
	defer b.Close()
	w := tsdb.NewMemory()

	consumer := pipeline.NewConsumer(b, w, "perf-noisy", logging.New(io.Discard, "error", "json"))
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = consumer.Run(cctx); close(done) }()
	time.Sleep(150 * time.Millisecond)

	const quietTenant, noisyTenant = "quiet-tenant", "noisy-tenant"
	var quietLat Latencies
	var firstErr atomic.Value

	publish := func(tenant string, n int, lat *Latencies, producers int) *sync.WaitGroup {
		var wg sync.WaitGroup
		per := n / producers
		if per < 1 {
			per = 1
			producers = n
		}
		for p := 0; p < producers; p++ {
			wg.Add(1)
			go func(worker int) {
				defer wg.Done()
				for i := 0; i < per; i++ {
					id := identity{
						tenant: tenant,
						agent:  fmt.Sprintf("%s-agent-%d", tenant, worker),
						server: fmt.Sprintf("svc-%d.example:443", i%50),
					}
					payload, e := proto.Marshal(buildResult(id))
					if e != nil {
						firstErr.CompareAndSwap(nil, e)
						return
					}
					t0 := time.Now()
					if e := b.Publish(cctx, bus.NetworkResultsTopic, []byte(tenant), payload); e != nil {
						firstErr.CompareAndSwap(nil, e)
						return
					}
					if lat != nil {
						lat.Record(time.Since(t0))
					}
				}
			}(p)
		}
		return &wg
	}

	quietN := cfg.QuietResults
	expectQuiet := (quietN / cfg.Producers) * cfg.Producers // what the workers actually send
	if quietN < cfg.Producers {
		expectQuiet = quietN
	}

	var noisyWG *sync.WaitGroup
	if withNoise {
		noisyWG = publish(noisyTenant, quietN*cfg.NoisyFactor, nil, cfg.Producers*2)
	}
	quietWG := publish(quietTenant, quietN, &quietLat, cfg.Producers)
	quietWG.Wait()
	if noisyWG != nil {
		noisyWG.Wait()
	}

	// Drain: wait until the quiet tenant's success series (one per result)
	// are all confirmed in the store.
	deadline := time.Now().Add(cfg.SettleTimeout)
	quietSeries := func() int {
		return len(w.Query("probectl_probe_success", map[string]string{"tenant_id": quietTenant}))
	}
	for quietSeries() < expectQuiet && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done

	if e := firstErr.Load(); e != nil {
		return 0, phaseCounts{}, false, e.(error)
	}

	counts.quiet = quietSeries()
	counts.noisy = len(w.Query("probectl_probe_success", map[string]string{"tenant_id": noisyTenant}))
	// Correctness: every quiet result landed under the quiet tenant — and the
	// store never mixed the neighbor's series into the quiet tenant's label set.
	quietCorrect = counts.quiet == expectQuiet
	return quietLat.Summary().P95, counts, quietCorrect, nil
}
