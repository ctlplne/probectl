package perf

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
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
	tenant string
	agent  string
	server string
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
	consumer := pipeline.NewConsumer(b, w, "perf", logging.New(io.Discard, "error", "json"))
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	consumerDone := make(chan struct{})
	go func() { _ = consumer.Run(cctx); close(consumerDone) }()
	// The in-memory bus only delivers to current subscribers; give the consumer a
	// moment to register before publishing.
	time.Sleep(150 * time.Millisecond)

	ids := buildIdentities(cfg)

	var (
		pubLat    Latencies
		published atomic.Int64
		firstErr  atomic.Value
	)
	start := time.Now()

	var wg sync.WaitGroup
	for p := 0; p < cfg.Producers; p++ {
		lo, hi := chunk(len(ids), cfg.Producers, p)
		wg.Add(1)
		go func(ids []identity) {
			defer wg.Done()
			for _, id := range ids {
				payload, err := proto.Marshal(buildResult(id))
				if err != nil {
					firstErr.CompareAndSwap(nil, err)
					return
				}
				t0 := time.Now()
				if err := b.Publish(cctx, bus.NetworkResultsTopic, []byte(id.tenant), payload); err != nil {
					firstErr.CompareAndSwap(nil, err)
					return
				}
				pubLat.Record(time.Since(t0))
				published.Add(1)
			}
		}(ids[lo:hi])
	}
	wg.Wait()

	// Wait for the consumer to drain the bus into the store.
	deadline := time.Now().Add(cfg.SettleTimeout)
	for confirmed() < expectedSeries && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	elapsed := time.Since(start)
	cancel()
	<-consumerDone

	if e := firstErr.Load(); e != nil {
		return IngestReport{}, e.(error)
	}

	got := confirmed()
	rep := IngestReport{
		Config:         cfg,
		Published:      int(published.Load()),
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

// buildIdentities expands the scenario into one identity per result. The
// (tenant, agent, server) tuple repeats ResultsPerTest times, modeling a test
// that runs repeatedly — distinct timestamps, same label set.
func buildIdentities(c IngestConfig) []identity {
	ids := make([]identity, 0, c.TotalResults())
	for t := 0; t < c.Tenants; t++ {
		tenant := fmt.Sprintf("tenant-%04d", t)
		for a := 0; a < c.AgentsPerTenant; a++ {
			agent := fmt.Sprintf("agent-%04d-%04d", t, a)
			for m := 0; m < c.TestsPerAgent; m++ {
				server := fmt.Sprintf("host-%04d-%04d-%04d.example", t, a, m)
				for r := 0; r < c.ResultsPerTest; r++ {
					ids = append(ids, identity{tenant: tenant, agent: agent, server: server})
				}
			}
		}
	}
	return ids
}

// buildResult constructs a representative successful probe result.
func buildResult(id identity) *resultv1.Result {
	return &resultv1.Result{
		TenantId:          id.tenant,
		AgentId:           id.agent,
		CanaryType:        "icmp",
		ServerAddress:     id.server,
		Success:           true,
		StartTimeUnixNano: time.Now().UnixNano(),
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
