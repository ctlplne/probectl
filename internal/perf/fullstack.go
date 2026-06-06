package perf

// The FULL-STACK load gate (U-005). The in-process scale gate (scale.go)
// proves the gate's mechanics on every CI pass but deliberately excludes the
// real transports — docs/scale-gate.md says so in its honesty notes. This
// harness closes that gap: the SAME tier profiles and SLOs drive synthetic
// agents through REAL Kafka (the D1 async producer), the REAL production
// consumer (D2 retry/DLQ + D3 cardinality caps), a REAL Prometheus via
// remote-write, and tenant-scoped PromQL queries back out of it —
// agents → ingest → Kafka → store → query, end to end.
//
// Two entry points, one harness (mirroring the in-process gate):
//   - S tier at CI scale: `make load-test-smoke` (the load-smoke ci job) —
//     proves the full-stack HARNESS on every pass.
//   - L/XL at scale 1: `make load-test TIER=L|XL` on reference hardware —
//     the human-scheduled run whose numbers go into docs/scale-gate.md and
//     flip the SLOs from PROVISIONAL.
//
// Each run namespaces its tenants ("<ns>-tenant-0000") so a persistent
// store cannot leak series between runs; run against a FRESH stack
// (`make compose-up`) — the consumer reads its topic from the start.

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// QueryCounter runs an instant count query against the populated store —
// (*tsdb.Prometheus).Count in production, a memory-store closure in tests.
type QueryCounter func(ctx context.Context, promql string) (float64, error)

// FullStackTargets locates the real stack.
type FullStackTargets struct {
	Brokers []string // Kafka bootstrap (e.g. localhost:9092)
	PromURL string   // Prometheus base URL (remote-write receiver enabled)
}

// FullStackReport is one full-stack gate run.
type FullStackReport struct {
	Scale          ScaleReport // profile, ingest numbers, SLO violations
	Namespace      string      // this run's tenant prefix
	UniqueSeries   int         // distinct series the run must materialize
	Confirmed      int         // distinct series actually visible in the store
	QueryP95       time.Duration
	TenantsQueried int

	// Pipeline diagnostics — where records stop when a run fails (the bus
	// produced count comes from the real Kafka client when present; the rest
	// from the consumer). A failed gate reads these to localize the break:
	// published≠produced ⇒ bus; produced but deadLettered/dropped ⇒ store
	// write (the consumer logs the verbatim error to stderr); produced+
	// written but 0 confirmed ⇒ query/store visibility.
	Published    int
	Produced     uint64
	ProduceFail  uint64
	ProduceShed  uint64
	Retried      uint64
	DeadLettered uint64
	Dropped      uint64
	SeriesCapped uint64
}

// Diagnostics renders the pipeline counters for the CI log.
func (r FullStackReport) Diagnostics() string {
	return fmt.Sprintf(
		"pipeline: published=%d produced=%d produce_fail=%d produce_shed=%d → confirmed=%d/%d series; consumer retried=%d dead_lettered=%d dropped=%d series_capped=%d",
		r.Published, r.Produced, r.ProduceFail, r.ProduceShed, r.Confirmed, r.UniqueSeries,
		r.Retried, r.DeadLettered, r.Dropped, r.SeriesCapped)
}

// String renders the row the operator copies into docs/scale-gate.md.
func (r FullStackReport) String() string {
	verdict := "PASS"
	if len(r.Scale.Violations) > 0 {
		verdict = "FAIL"
	}
	return fmt.Sprintf(
		"full-stack %s (ci=%t ns=%s): %.0f results/s end-to-end; publish p95 %s; query p95 %s over %d tenants; %d/%d series confirmed; %s",
		r.Scale.Profile.Tier, r.Scale.AtCIScale, r.Namespace,
		r.Scale.Ingest.Throughput, round(r.Scale.Ingest.PublishLatency.P95),
		round(r.QueryP95), r.TenantsQueried, r.Confirmed, r.UniqueSeries, verdict)
}

// uniqueSeriesFor is the number of DISTINCT series a scenario materializes:
// one per (tenant, agent, test) × seriesPerResult. Repeated results re-write
// the same series, so a persistent store is confirmed on series, not samples.
func uniqueSeriesFor(c IngestConfig) int {
	return c.Tenants * c.AgentsPerTenant * c.TestsPerAgent * seriesPerResult
}

// successMetric is the per-result success series the pipeline writes — the
// query leg counts it per tenant (one series per agent×test).
const successMetric = "probectl_probe_success"

// DriveFullStack drives one tier profile through bus → consumer → writer and
// confirms it back OUT of the store via count: settle on this run's unique
// series, then per-tenant correctness + query latency. The bus/writer/count
// seams keep the driver unit-testable; RunFullStackGate wires the real stack.
func DriveFullStack(ctx context.Context, b bus.Bus, w tsdb.Writer, count QueryCounter, profile Profile, atCIScale bool, ns string) (FullStackReport, error) {
	cfg := profile.Ingest
	cfg.Namespace = ns
	if cfg.SettleTimeout <= 0 {
		cfg.SettleTimeout = 2 * time.Minute
	}
	rep := FullStackReport{Namespace: ns, UniqueSeries: uniqueSeriesFor(cfg)}

	// Consumer errors (store-write failures incl. the verbatim Prometheus
	// remote-write status/body) go to stderr so a failed gate is diagnosable
	// from the CI log — not swallowed.
	consumer := pipeline.NewConsumer(b, w, "loadgate-"+ns, logging.New(os.Stderr, "error", "json"))
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	consumerDone := make(chan struct{})
	go func() { _ = consumer.Run(cctx); close(consumerDone) }()
	time.Sleep(150 * time.Millisecond)

	// Publish the tier's load (the "agents").
	var pubLat Latencies
	start := time.Now()
	published, pubErr := publishIdentities(cctx, b, buildIdentities(cfg), cfg.Producers, &pubLat)
	rep.Published = published
	if pubErr != nil {
		cancel()
		<-consumerDone
		return rep, fmt.Errorf("perf: full-stack publish: %w", pubErr)
	}

	// Settle: every distinct series of THIS run visible via the query path.
	selector := fmt.Sprintf(`count({tenant_id=~"%s-tenant-.*"})`, ns)
	deadline := time.Now().Add(cfg.SettleTimeout)
	confirmed := 0.0
	for time.Now().Before(deadline) {
		v, err := count(ctx, selector)
		if err == nil {
			confirmed = v
			if int(v) >= rep.UniqueSeries {
				break
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	elapsed := time.Since(start)
	cancel()
	<-consumerDone

	rep.Confirmed = int(confirmed)
	// Localize a break: bus produce outcomes (real Kafka only) + consumer
	// loss accounting.
	if bs, ok := b.(interface{ Stats() bus.PublishStats }); ok {
		st := bs.Stats()
		rep.Produced, rep.ProduceFail, rep.ProduceShed = st.Produced, st.Failed, st.Shed
	}
	cs := consumer.Stats()
	rep.Retried, rep.DeadLettered, rep.Dropped = cs.Retried, cs.DeadLettered, cs.Dropped
	rep.SeriesCapped = consumer.CardinalityStats().Dropped

	ing := IngestReport{
		Config:         cfg,
		Published:      published,
		SeriesWritten:  int(confirmed),
		Elapsed:        elapsed,
		PublishLatency: pubLat.Summary(),
	}
	if elapsed > 0 {
		ing.Throughput = float64(published) / elapsed.Seconds()
	}
	rep.Scale = ScaleReport{Profile: profile, Ingest: ing, AtCIScale: atCIScale}
	rep.Scale.evaluate()
	if int(confirmed) < rep.UniqueSeries {
		rep.Scale.Violations = append(rep.Scale.Violations, fmt.Sprintf(
			"%s: INGEST INCOMPLETE — %d/%d series confirmed in the store within %s",
			profile.Tier, int(confirmed), rep.UniqueSeries, cfg.SettleTimeout))
	}

	// Query leg: tenant-scoped reads over the populated store — correctness
	// (each tenant sees exactly its own agents×tests success series) and
	// latency.
	perTenant := cfg.AgentsPerTenant * cfg.TestsPerAgent
	sample := cfg.Tenants
	if sample > 8 {
		sample = 8
	}
	var qLat Latencies
	for t := 0; t < sample; t++ {
		expr := fmt.Sprintf(`count(%s{tenant_id="%s-tenant-%04d"})`, successMetric, ns, t)
		t0 := time.Now()
		v, err := count(ctx, expr)
		if err != nil {
			rep.Scale.Violations = append(rep.Scale.Violations,
				fmt.Sprintf("%s: query leg failed for tenant %04d: %v", profile.Tier, t, err))
			continue
		}
		qLat.Record(time.Since(t0))
		if int(v) != perTenant {
			rep.Scale.Violations = append(rep.Scale.Violations, fmt.Sprintf(
				"%s: tenant %04d sees %d success series, want exactly %d (scoping/completeness)",
				profile.Tier, t, int(v), perTenant))
		}
	}
	rep.TenantsQueried = sample
	rep.QueryP95 = qLat.Summary().P95
	return rep, nil
}

// RunFullStackGate wires the REAL stack — Kafka producer/consumer and the
// Prometheus remote-write writer + instant-query counter — and drives one
// tier at the given scale (scale 1 = the reference-hardware run).
func RunFullStackGate(ctx context.Context, tier Tier, scale float64, targets FullStackTargets) (FullStackReport, error) {
	profile, err := ProfileFor(tier, scale)
	if err != nil {
		return FullStackReport{}, err
	}
	if len(targets.Brokers) == 0 || targets.PromURL == "" {
		return FullStackReport{}, fmt.Errorf("perf: full-stack gate needs Kafka brokers and a Prometheus URL")
	}

	b, err := bus.NewKafka(targets.Brokers, 0)
	if err != nil {
		return FullStackReport{}, fmt.Errorf("perf: full-stack kafka: %w", err)
	}
	defer b.Close()
	w := tsdb.NewPrometheus(targets.PromURL)

	nonce, err := crypto.Random(4)
	if err != nil {
		return FullStackReport{}, err
	}
	ns := fmt.Sprintf("ls%x", nonce)
	return DriveFullStack(ctx, b, w, w.Count, profile, scale < 1, ns)
}
