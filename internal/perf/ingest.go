// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package perf

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

// seriesPerResult is how many TSDB series one probe result produces in the
// scenarios this harness drives: probectl_probe_success + _duration_seconds + one
// custom metric (rtt.avg.ms). It is used to know when ingestion has settled.
const seriesPerResult = 3

// IngestConfig describes a synthetic ingest load: N agents per tenant, each
// running M tests, each producing R results, across T tenants. The total result
// count is the product; producers publish them concurrently.
type IngestConfig struct {
	Tenants         int
	AgentsPerTenant int
	TestsPerAgent   int
	ResultsPerTest  int
	Producers       int
	SettleTimeout   time.Duration
	// Namespace, when set, prefixes every tenant id ("<ns>-tenant-0000").
	// The full-stack gate (U-005) uses it to isolate one run's series in a
	// persistent store; the in-process harness leaves it empty.
	Namespace string
}

// TotalResults is the number of results the scenario drives.
func (c IngestConfig) TotalResults() int {
	return c.Tenants * c.AgentsPerTenant * c.TestsPerAgent * c.ResultsPerTest
}

// IngestReport is the outcome of a DriveIngest run.
type IngestReport struct {
	Config         IngestConfig
	Published      int
	SeriesWritten  int
	Elapsed        time.Duration
	Throughput     float64 // results/sec, end-to-end (publish → confirmed in TSDB)
	PublishLatency LatencyStat
}

// String renders the report for logs and the baseline doc.
func (r IngestReport) String() string {
	c := r.Config
	return fmt.Sprintf(
		"ingest: tenants=%d agents/t=%d tests/a=%d results/test=%d → %d results in %s = %.0f results/s; publish[%s]",
		c.Tenants, c.AgentsPerTenant, c.TestsPerAgent, c.ResultsPerTest,
		r.Published, round(r.Elapsed), r.Throughput, r.PublishLatency)
}

// identity names the source of one synthetic result.
type identity struct {
	tenant        string
	agent         string
	server        string
	eventUnixNano int64
}

// DriveIngest runs the lightweight ingest path under load: it publishes
// TotalResults probe results to the network-results topic, runs a pipeline
// consumer writing to w, and waits until every result's series are confirmed
// (confirmed() reaches Total*seriesPerResult) or SettleTimeout elapses. It
// returns end-to-end throughput (publish → confirmed) and publish latency.
//
// confirmed reports how many series have reached the store (e.g. tsdb.Memory.Len);
// passing it keeps the harness decoupled from the writer implementation so S48
// can swap a Prometheus writer with a query-based confirmation.
func DriveIngest(ctx context.Context, b bus.Bus, w tsdb.Writer, confirmed func() int, cfg IngestConfig) (IngestReport, error) {
	if cfg.Producers <= 0 {
		cfg.Producers = 1
	}
	if cfg.SettleTimeout <= 0 {
		cfg.SettleTimeout = 30 * time.Second
	}
	total := cfg.TotalResults()
	if total <= 0 {
		return IngestReport{}, fmt.Errorf("perf: empty ingest scenario (%+v)", cfg)
	}
	expectedSeries := total * seriesPerResult

	// Start the consumer (agents → bus → consumer → TSDB).
	consumer := pipeline.NewConsumer(b, w, "perf", logging.New(io.Discard, "error", "json")).
		WithWriteWorkers(ingestHarnessWriteWorkers(cfg)).
		WithWriteQueueDepth(ingestHarnessWriteQueueDepth(cfg))
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	consumerDone := make(chan struct{})
	go func() { _ = consumer.Run(cctx); close(consumerDone) }()
	// SCALE-003 / TEST-002: the in-memory bus is a LIVE pub/sub — it only delivers
	// to subscribers present at publish time. Synchronize on the consumer's
	// registration instead of sleeping a guessed 150ms: under load that sleep was
	// non-deterministic and silently dropped any results published before the
	// consumer subscribed (an undercount that flaked the settle assertion). On a
	// bus without this capability (Kafka, where a group joins independently of the
	// producer) we proceed immediately.
	if w, ok := b.(bus.SubscriberWaiter); ok {
		wctx, wcancel := context.WithTimeout(cctx, 5*time.Second)
		if !w.WaitForSubscribers(wctx, bus.NetworkResultsTopic, 1) {
			wcancel()
			return IngestReport{}, fmt.Errorf("perf: consumer did not subscribe to %s within 5s", bus.NetworkResultsTopic)
		}
		wcancel()
	}

	ids := buildIdentities(cfg)

	var pubLat Latencies
	start := time.Now()
	published, pubErr := publishIdentities(cctx, b, ids, cfg.Producers, cfg.ResultsPerTest, &pubLat)

	// Wait for the consumer to drain the bus into the store. This is a settle
	// POLL on a monotonic completion signal (confirmed() rises to
	// expectedSeries), not a guessed delay: it terminates deterministically the
	// instant every series lands, bounded by SettleTimeout. WaitForSubscribers
	// does not apply here — the subscriber is long since registered; what we
	// await is downstream drain, which only confirmed() can report. The short
	// sleep is just the poll interval.
	deadline := time.Now().Add(cfg.SettleTimeout)
	for confirmed() < expectedSeries && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	elapsed := time.Since(start)
	cancel()
	<-consumerDone

	if pubErr != nil {
		return IngestReport{}, pubErr
	}

	got := confirmed()
	rep := IngestReport{
		Config:         cfg,
		Published:      published,
		SeriesWritten:  got,
		Elapsed:        elapsed,
		PublishLatency: pubLat.Summary(),
	}
	if elapsed > 0 {
		rep.Throughput = float64(rep.Published) / elapsed.Seconds()
	}
	if got < expectedSeries {
		return rep, fmt.Errorf("perf: ingest incomplete — confirmed %d/%d series within %s", got, expectedSeries, cfg.SettleTimeout)
	}
	return rep, nil
}

// publishIdentities marshals and publishes one result per identity across
// `producers` concurrent workers, recording per-publish latency. It returns
// the count published and the first error encountered (workers stop on it).
func publishIdentities(ctx context.Context, b bus.Bus, ids []identity, producers, resultsPerSeries int, lat *Latencies) (int, error) {
	var (
		published atomic.Int64
		firstErr  atomic.Value
		wg        sync.WaitGroup
	)
	if resultsPerSeries < 1 {
		resultsPerSeries = 1
	}
	for p := 0; p < producers; p++ {
		lo, hi := chunkSeries(len(ids), resultsPerSeries, producers, p)
		wg.Add(1)
		go func(ids []identity) {
			defer wg.Done()
			var localLat Latencies
			for _, id := range ids {
				payload, err := proto.Marshal(buildResult(id))
				if err != nil {
					firstErr.CompareAndSwap(nil, err)
					return
				}
				t0 := time.Now()
				if err := b.Publish(ctx, bus.NetworkResultsTopic, bus.TenantKey(id.tenant, id.agent), payload); err != nil {
					firstErr.CompareAndSwap(nil, err)
					return
				}
				localLat.Record(time.Since(t0))
				published.Add(1)
			}
			lat.Add(&localLat)
		}(ids[lo:hi])
	}
	wg.Wait()
	if e := firstErr.Load(); e != nil {
		return int(published.Load()), e.(error)
	}
	return int(published.Load()), nil
}

func chunkSeries(n, groupSize, producers, worker int) (int, int) {
	if groupSize <= 1 {
		return chunk(n, producers, worker)
	}
	groups := n / groupSize
	if n%groupSize != 0 {
		return chunk(n, producers, worker)
	}
	glo, ghi := chunk(groups, producers, worker)
	return glo * groupSize, ghi * groupSize
}

func ingestHarnessWriteWorkers(cfg IngestConfig) int {
	if cfg.TotalResults() < 100_000 {
		return 0
	}
	workers := cfg.Producers * 16
	if workers < 64 {
		workers = 64
	}
	if workers > 512 {
		workers = 512
	}
	return workers
}

func ingestHarnessWriteQueueDepth(cfg IngestConfig) int {
	workers := ingestHarnessWriteWorkers(cfg)
	if workers == 0 {
		return 0
	}
	return workers * 32
}

// buildIdentities expands the scenario into one identity per result. The
// (tenant, agent, server) tuple repeats ResultsPerTest times, modeling a test
// that runs repeatedly — distinct timestamps, same label set.
func buildIdentities(c IngestConfig) []identity {
	ids := make([]identity, 0, c.TotalResults())
	prefix := ""
	if c.Namespace != "" {
		prefix = c.Namespace + "-"
	}
	baseUnixNano := time.Now().Add(-ingestTimestampSpan(c)).UnixNano()
	for t := 0; t < c.Tenants; t++ {
		tenant := fmt.Sprintf("%stenant-%04d", prefix, t)
		for a := 0; a < c.AgentsPerTenant; a++ {
			agent := fmt.Sprintf("agent-%04d-%04d", t, a)
			for m := 0; m < c.TestsPerAgent; m++ {
				server := fmt.Sprintf("host-%04d-%04d-%04d.example", t, a, m)
				for r := 0; r < c.ResultsPerTest; r++ {
					ids = append(ids, identity{
						tenant:        tenant,
						agent:         agent,
						server:        server,
						eventUnixNano: baseUnixNano + int64(r)*int64(time.Second),
					})
				}
			}
		}
	}
	return ids
}

func ingestTimestampSpan(c IngestConfig) time.Duration {
	points := c.ResultsPerTest
	if points < 1 {
		points = 1
	}
	return time.Duration(points+2) * time.Second
}

// buildResult constructs a representative successful probe result.
func buildResult(id identity) *resultv1.Result {
	return &resultv1.Result{
		TenantId:          id.tenant,
		AgentId:           id.agent,
		CanaryType:        "icmp",
		ServerAddress:     id.server,
		Success:           true,
		StartTimeUnixNano: id.eventUnixNano,
		DurationNano:      5_000_000,
		Metrics:           map[string]float64{"rtt.avg.ms": 12.5},
	}
}

// chunk splits n items into p contiguous chunks and returns the [lo,hi) bounds
// of the i-th chunk.
func chunk(n, p, i int) (int, int) {
	base := n / p
	rem := n % p
	lo := i*base + min(i, rem)
	hi := lo + base
	if i < rem {
		hi++
	}
	return lo, hi
}
