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
	"sort"
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
	// Repeats is the number of (solo, noisy) PAIRS to run; the reported
	// inflation is the MEDIAN pair's (default 3 — see the U-055 note below).
	Repeats int
}

// NoisyReport is the scenario outcome.
type NoisyReport struct {
	Ran          bool
	SoloP95      time.Duration // quiet tenant alone (median pair)
	NoisyP95     time.Duration // quiet tenant beside the flood (median pair)
	Inflation    float64       // NoisyP95 / SoloP95 of the median pair
	QuietCorrect bool          // every quiet series landed, correctly scoped, in EVERY phase
	QuietSeries  int
	NoisySeries  int
	Pairs        int // (solo, noisy) pairs run
}

// String renders the report for logs and docs.
func (r NoisyReport) String() string {
	return fmt.Sprintf("noisy-neighbor: solo p95 %s → under-noise p95 %s = %.2fx inflation (median of %d pairs); quiet correct=%t",
		round(r.SoloP95), round(r.NoisyP95), r.Inflation, r.Pairs, r.QuietCorrect)
}

// DriveNoisyNeighbor runs the scenario on the lightweight in-process stack
// and reports the quiet tenant's experience.
//
// De-flaking design (U-055): each comparison is a temporally-adjacent
// (solo, noisy) PAIR — host-wide slowness (shared CI runners, GC, scheduler
// stalls) hits both sides of the same pair, so the RATIO self-normalizes —
// and the scenario runs Repeats pairs, reporting the MEDIAN pair, so one
// transient stall cannot fake a noisy neighbor. This is what lets CI gate at
// the same documented 5ms materiality floor as reference hardware instead of
// a loosened one. Correctness is AND-ed across every phase of every pair:
// a single mis-scoped or lost result fails the gate regardless of timing.
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
	if cfg.Repeats <= 0 {
		cfg.Repeats = 3
	}

	pairs := make([]noisyPair, 0, cfg.Repeats)
	for k := 0; k < cfg.Repeats; k++ {
		// Phase A — solo: the quiet tenant alone.
		soloP95, _, soloOK, err := runPhase(ctx, cfg, false)
		if err != nil {
			return NoisyReport{}, fmt.Errorf("perf: solo phase (pair %d): %w", k+1, err)
		}
		// Phase B — the same quiet workload beside a flooding neighbor,
		// immediately after its own baseline.
		noisyP95, counts, noisyOK, err := runPhase(ctx, cfg, true)
		if err != nil {
			return NoisyReport{}, fmt.Errorf("perf: noisy phase (pair %d): %w", k+1, err)
		}
		pairs = append(pairs, newNoisyPair(soloP95, noisyP95, counts, soloOK && noisyOK))
	}
	return aggregatePairs(pairs), nil
}

// noisyPair is one temporally-adjacent (solo, noisy) measurement.
type noisyPair struct {
	solo, noisy time.Duration
	inflation   float64
	counts      phaseCounts
	correct     bool
}

func newNoisyPair(solo, noisy time.Duration, counts phaseCounts, correct bool) noisyPair {
	base := solo
	if base < time.Microsecond {
		base = time.Microsecond
	}
	inf := float64(noisy) / float64(base)
	if inf < 1 {
		inf = 1 // contention can only be ≥ solo; clamp jitter
	}
	return noisyPair{solo: solo, noisy: noisy, inflation: inf, counts: counts, correct: correct}
}

// aggregatePairs reduces the pairs to the report: the MEDIAN pair carries
// the timing verdict (a transient host stall poisons at most one pair);
// correctness must hold in every pair.
func aggregatePairs(pairs []noisyPair) NoisyReport {
	rep := NoisyReport{Ran: true, Pairs: len(pairs), QuietCorrect: true}
	for _, p := range pairs {
		rep.QuietCorrect = rep.QuietCorrect && p.correct
	}
	sorted := append([]noisyPair(nil), pairs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].inflation < sorted[j].inflation })
	med := sorted[(len(sorted)-1)/2]
	rep.SoloP95, rep.NoisyP95, rep.Inflation = med.solo, med.noisy, med.inflation
	rep.QuietSeries, rep.NoisySeries = med.counts.quiet, med.counts.noisy
	return rep
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
