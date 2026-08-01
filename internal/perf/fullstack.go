// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
//   - L/XL/XXL at scale 1: `make load-test TIER=L|XL|XXL` on reference hardware —
//     the human-scheduled run whose numbers go into docs/scale-gate.md and
//     flip the SLOs from PROVISIONAL.
//
// Each run namespaces its tenants ("<ns>-tenant-0000") so a persistent
// store cannot leak series between runs; run against a FRESH stack
// (`make compose-up`) — the consumer reads its topic from the start.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/store/tsdb"
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
	Received     uint64
	Stored       uint64
	Retried      uint64
	DeadLettered uint64
	Dropped      uint64
	WriteQueued  uint64
	SeriesCapped uint64
}

// Diagnostics renders the pipeline counters for the CI log.
func (r FullStackReport) Diagnostics() string {
	return fmt.Sprintf(
		"pipeline: published=%d produced=%d produce_fail=%d produce_shed=%d → received=%d stored=%d confirmed=%d/%d series; consumer retried=%d dead_lettered=%d dropped=%d write_queue_saturated=%d series_capped=%d",
		r.Published, r.Produced, r.ProduceFail, r.ProduceShed, r.Received, r.Stored, r.Confirmed, r.UniqueSeries,
		r.Retried, r.DeadLettered, r.Dropped, r.WriteQueued, r.SeriesCapped)
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

// fullStackKafkaFlushTimeout is a phase bound, not the whole load-test budget.
// A missing broker/topic must fail this warmup promptly; otherwise franz-go can
// legitimately keep retrying until the 10-minute outer scale context expires,
// hiding the real dependency failure behind a suite-wide timeout.
const (
	fullStackKafkaFlushTimeout = 20 * time.Second
	// A freshly created single-node KRaft broker can report API health before
	// its first consumer-group coordinator/offset topic is ready. Keep this
	// setup allowance separate from the measured load and settle windows.
	fullStackReadinessTimeout       = 60 * time.Second
	fullStackReadinessProbeInterval = time.Second
)

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
	consumer := pipeline.NewConsumer(b, w, "loadgate-"+ns, logging.New(os.Stderr, "error", "json")).
		WithWriteWorkers(fullStackWriteWorkers(profile, atCIScale)).
		WithWriteQueueDepth(fullStackWriteQueueDepth(profile, atCIScale))
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	consumerErr := make(chan error, 1)
	go func() { consumerErr <- consumer.Run(cctx) }()
	time.Sleep(150 * time.Millisecond)
	select {
	case err := <-consumerErr:
		if err != nil {
			return rep, fmt.Errorf("perf: full-stack consumer exited before publish: %w", err)
		}
		return rep, errors.New("perf: full-stack consumer exited before publish")
	default:
	}
	if err := waitFullStackReady(cctx, b, count, ns, consumerErr); err != nil {
		cancel()
		return rep, err
	}

	// Publish the tier's load (the "agents").
	var pubLat Latencies
	start := time.Now()
	published, pubErr := publishIdentities(cctx, b, buildIdentities(cfg), cfg.Producers, cfg.ResultsPerTest, &pubLat)
	rep.Published = published
	if pubErr != nil {
		cancel()
		<-consumerErr
		return rep, fmt.Errorf("perf: full-stack publish: %w", pubErr)
	}

	// Settle: every distinct series of THIS run visible via the query path.
	confirmRange := promDuration(fullStackConfirmationRange(cfg))
	selector := fullStackTotalSeriesExpr(ns, confirmRange)
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
	if err := <-consumerErr; err != nil {
		return rep, fmt.Errorf("perf: full-stack consumer: %w", err)
	}

	rep.Confirmed = int(confirmed)
	// Localize a break: bus produce outcomes (real Kafka only) + consumer
	// loss accounting.
	if bs, ok := b.(interface{ Stats() bus.PublishStats }); ok {
		st := bs.Stats()
		rep.Produced, rep.ProduceFail, rep.ProduceShed = st.Produced, st.Failed, st.Shed
	}
	cs := consumer.Stats()
	is := consumer.IntegrityStats()
	rep.Received, rep.Stored = is.Received, is.Stored
	rep.Retried, rep.DeadLettered, rep.Dropped, rep.WriteQueued = cs.Retried, cs.DeadLettered, cs.Dropped, cs.WriteQueueSaturated
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
	// latency. Enumerate every tenant: total namespace counts can hide a broken
	// tenant-specific query path, and sampling only the first few tenants misses
	// exactly the L/XL/XXL many-tenant skew this gate is supposed to catch.
	perTenant := cfg.AgentsPerTenant * cfg.TestsPerAgent
	var qLat Latencies
	for t := 0; t < cfg.Tenants; t++ {
		expr := fmt.Sprintf(`count(count_over_time(%s{tenant_id="%s-tenant-%04d"}[%s]))`, successMetric, ns, t, confirmRange)
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
	rep.TenantsQueried = cfg.Tenants
	rep.QueryP95 = qLat.Summary().P95
	return rep, nil
}

func fullStackConfirmationRange(cfg IngestConfig) time.Duration {
	span := ingestTimestampSpan(cfg) + 2*time.Minute
	if span < 10*time.Minute {
		return 10 * time.Minute
	}
	return span
}

func promDuration(d time.Duration) string {
	if d <= 0 {
		return "1s"
	}
	sec := int64((d + time.Second - 1) / time.Second)
	if sec < 1 {
		sec = 1
	}
	return fmt.Sprintf("%ds", sec)
}

func fullStackTotalSeriesExpr(ns, rng string) string {
	return fmt.Sprintf(
		`count(count_over_time(probectl_probe_success{tenant_id=~"%[1]s-tenant-.*"}[%[2]s])) + count(count_over_time(probectl_probe_duration_seconds{tenant_id=~"%[1]s-tenant-.*"}[%[2]s])) + count(count_over_time(probectl_probe_rtt_avg_ms{tenant_id=~"%[1]s-tenant-.*"}[%[2]s]))`,
		ns, rng)
}

func waitFullStackReady(ctx context.Context, b bus.Bus, count QueryCounter, ns string, consumerErr <-chan error) error {
	tenant := ns + "-ready"
	if err := publishFullStackReadiness(ctx, b, tenant); err != nil {
		return err
	}

	readyCtx, cancel := context.WithTimeout(ctx, fullStackReadinessTimeout)
	defer cancel()
	probeTicker := time.NewTicker(fullStackReadinessProbeInterval)
	defer probeTicker.Stop()
	queryTicker := time.NewTicker(250 * time.Millisecond)
	defer queryTicker.Stop()
	query := fmt.Sprintf(`count(%s{tenant_id="%s"})`, successMetric, tenant)
	for {
		v, err := count(readyCtx, query)
		if err == nil && v >= 1 {
			return nil
		}
		select {
		case consumerRunErr := <-consumerErr:
			if consumerRunErr != nil {
				return fmt.Errorf("perf: full-stack consumer exited during readiness: %w", consumerRunErr)
			}
			return errors.New("perf: full-stack consumer exited during readiness")
		case <-readyCtx.Done():
			if err != nil {
				return fmt.Errorf("perf: readiness query: %w", err)
			}
			return fmt.Errorf("perf: readiness result not visible in Prometheus within %s", fullStackReadinessTimeout)
		case <-probeTicker.C:
			// A newly created consumer group configured to start at the end can
			// be assigned just after the first probe lands. Re-publishing this
			// run-scoped probe turns readiness into an active handshake instead
			// of sleeping and hoping the assignment won the race.
			if err := publishFullStackReadiness(readyCtx, b, tenant); err != nil {
				return err
			}
		case <-queryTicker.C:
		}
	}
}

func publishFullStackReadiness(ctx context.Context, b bus.Bus, tenant string) error {
	payload, err := proto.Marshal(buildResult(identity{
		tenant:        tenant,
		agent:         "ready-agent",
		server:        "ready.example:443",
		eventUnixNano: time.Now().UnixNano(),
	}))
	if err != nil {
		return fmt.Errorf("perf: readiness result: %w", err)
	}
	if err := b.Publish(ctx, bus.NetworkResultsTopic, []byte(tenant), payload); err != nil {
		return fmt.Errorf("perf: readiness publish: %w", err)
	}
	return flushFullStackBus(ctx, b, "readiness")
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

	// The gate runs against a FRESH stack whose results topic does not exist
	// yet, and franz-go's default metadata requests forbid topic creation —
	// every record then fails with unknown-topic after retries (the first
	// load-smoke run: published=8 produced=0 produce_fail=8). Production
	// topics are operator-provisioned; the harness provisions its own via
	// the broker's auto-create on first produce.
	b, err := bus.NewKafka(targets.Brokers, fullStackKafkaMaxBuffered(profile, scale), kgo.AllowAutoTopicCreation())
	if err != nil {
		return FullStackReport{}, fmt.Errorf("perf: full-stack kafka: %w", err)
	}
	b.WithSubscribeWorkers(fullStackSubscribeWorkers(profile, scale))
	b.WithSubscribeFromEnd()
	defer b.Close()
	if err := warmKafkaTopic(ctx, b); err != nil {
		return FullStackReport{}, err
	}
	prom := tsdb.NewPrometheus(targets.PromURL)
	w := tsdb.NewBatchingWriter(prom, fullStackBatchSeries(profile, scale), fullStackBatchWait(scale))
	defer w.Close()

	nonce, err := crypto.Random(4)
	if err != nil {
		return FullStackReport{}, err
	}
	ns := fmt.Sprintf("ls%x", nonce)
	return DriveFullStack(ctx, b, w, prom.Count, profile, scale < 1, ns)
}

func warmKafkaTopic(ctx context.Context, b bus.Bus) error {
	payload, err := proto.Marshal(buildResult(identity{
		tenant:        "perf-warmup",
		agent:         "perf-warmup-agent",
		server:        "perf-warmup.example:443",
		eventUnixNano: time.Now().UnixNano(),
	}))
	if err != nil {
		return fmt.Errorf("perf: warmup result: %w", err)
	}
	if err := b.Publish(ctx, bus.NetworkResultsTopic, []byte("perf-warmup"), payload); err != nil {
		return fmt.Errorf("perf: warmup publish: %w", err)
	}
	if err := flushFullStackBus(ctx, b, "warmup"); err != nil {
		return err
	}
	return nil
}

func flushFullStackBus(ctx context.Context, b bus.Bus, phase string) error {
	f, ok := b.(bus.Flusher)
	if !ok {
		return nil
	}
	flushCtx, cancel := context.WithTimeout(ctx, fullStackKafkaFlushTimeout)
	defer cancel()
	if err := f.Flush(flushCtx); err != nil {
		return fmt.Errorf("perf: %s flush: %w", phase, err)
	}
	return nil
}

func fullStackKafkaMaxBuffered(profile Profile, scale float64) int {
	if scale < 1 {
		return bus.DefaultMaxBuffered
	}
	n := profile.Ingest.TotalResults()
	if n < bus.DefaultMaxBuffered {
		return bus.DefaultMaxBuffered
	}
	return n
}

func fullStackSubscribeWorkers(profile Profile, scale float64) int {
	if scale < 1 {
		return 1
	}
	return fullStackWorkerCount(profile)
}

func fullStackWriteWorkers(profile Profile, atCIScale bool) int {
	if atCIScale {
		return 0
	}
	return fullStackWorkerCount(profile)
}

func fullStackWriteQueueDepth(profile Profile, atCIScale bool) int {
	if atCIScale {
		return 0
	}
	return fullStackWorkerCount(profile) * 32
}

func fullStackWorkerCount(profile Profile) int {
	workers := profile.Ingest.Producers * 16
	if workers < 64 {
		workers = 64
	}
	if workers > 512 {
		workers = 512
	}
	return workers
}

func fullStackBatchSeries(_ Profile, scale float64) int {
	if scale < 1 {
		return 500
	}
	return 5000
}

func fullStackBatchWait(scale float64) time.Duration {
	if scale < 1 {
		return 50 * time.Millisecond
	}
	return time.Millisecond
}
