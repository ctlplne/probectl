// SPDX-License-Identifier: LicenseRef-probectl-TBD

package perf

// The FULL-STACK flow load gate closes the SCALE-001 honesty gap: flow-plane
// scale is no longer proven only by the in-memory bus/store harness. This path
// publishes normal flow batches through REAL Kafka, drains them with the
// production FlowConsumer, writes to REAL ClickHouse through flowstore, and
// confirms the rows back out through tenant-scoped TopTalkers queries.

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
)

const (
	fullStackFlowBatchSize = 5_000
	maxFlowQueryP95        = 2 * time.Second
	maxFlowInsertP95       = 2 * time.Second
)

// FullStackFlowTargets locates the real flow stack.
type FullStackFlowTargets struct {
	Brokers      []string // Kafka bootstrap (e.g. localhost:9092)
	FlowStoreURL string   // ClickHouse HTTP URL (e.g. http://probectl:probectl@localhost:8123)
}

// FullStackFlowReport is one real-stack flow gate run.
type FullStackFlowReport struct {
	Profile   Profile
	AtCIScale bool
	Namespace string

	Records        int
	Stored         int
	Batches        int
	TenantsQueried int
	Elapsed        time.Duration
	RecordsSec     float64
	PublishLatency LatencyStat
	FlushLatency   time.Duration
	InsertLatency  LatencyStat
	QueryP95       time.Duration

	Published    int
	Produced     uint64
	ProduceFail  uint64
	ProduceShed  uint64
	Rejected     uint64
	Retried      uint64
	DeadLettered uint64
	Dropped      uint64

	PartsBefore flowstore.PartPressure
	PartsAfter  flowstore.PartPressure
	MaxNewParts int

	Violations []string
}

// Diagnostics renders the flow pipeline counters for CI logs.
func (r FullStackFlowReport) Diagnostics() string {
	return fmt.Sprintf(
		"flow pipeline: published=%d batches produced=%d produce_fail=%d produce_shed=%d → stored=%d/%d rows; rejected=%d retried=%d dead_lettered=%d dropped=%d; active_parts before=%d after=%d max_new=%d rows_after=%d",
		r.Published, r.Produced, r.ProduceFail, r.ProduceShed, r.Stored, r.Records,
		r.Rejected, r.Retried, r.DeadLettered, r.Dropped,
		r.PartsBefore.ActiveParts, r.PartsAfter.ActiveParts, r.MaxNewParts, r.PartsAfter.Rows)
}

// String renders the row the operator copies into docs/scale-gate.md.
func (r FullStackFlowReport) String() string {
	verdict := "PASS"
	if len(r.Violations) > 0 {
		verdict = "FAIL"
	}
	return fmt.Sprintf(
		"full-stack-flow %s (ci=%t ns=%s): %.0f flows/s; insert p95 %s; query p95 %s over %d tenants; %d/%d rows confirmed; active_parts +%d/%d; %s",
		r.Profile.Tier, r.AtCIScale, r.Namespace, r.RecordsSec,
		round(r.InsertLatency.P95), round(r.QueryP95), r.TenantsQueried,
		r.Stored, r.Records, max(0, r.PartsAfter.ActiveParts-r.PartsBefore.ActiveParts),
		r.MaxNewParts, verdict)
}

type timedFlowStore struct {
	flowstore.Store
	lat *Latencies
}

func (s *timedFlowStore) Insert(ctx context.Context, rows []flowstore.Row) error {
	start := time.Now()
	err := s.Store.Insert(ctx, rows)
	s.lat.Record(time.Since(start))
	return err
}

type flowTenantLoad struct {
	ID       string
	Agent    string
	Source   string
	Exporter string
	Expected int
}

// DriveFullStackFlow drives one tier profile through Kafka → FlowConsumer →
// ClickHouse and confirms per-tenant completeness via the product read path.
func DriveFullStackFlow(ctx context.Context, b bus.Bus, st flowstore.Store, partPressure func(context.Context) (flowstore.PartPressure, error), profile Profile, atCIScale bool, ns string) (FullStackFlowReport, error) {
	cfg := profile.Ingest
	if cfg.Tenants < 1 {
		cfg.Tenants = 1
	}
	if cfg.SettleTimeout <= 0 {
		cfg.SettleTimeout = 2 * time.Minute
	}
	records := cfg.TotalResults() * 4
	if records < 200 {
		records = 200
	}
	tenants := buildFlowTenantLoad(ns, cfg.Tenants, records)
	maxNewParts := max(256, batchesFor(records, fullStackFlowBatchSize)+cfg.Tenants*4)
	rep := FullStackFlowReport{
		Profile:        profile,
		AtCIScale:      atCIScale,
		Namespace:      ns,
		Records:        records,
		TenantsQueried: cfg.Tenants,
		MaxNewParts:    maxNewParts,
	}
	topic, err := bus.TopicFor(ns, bus.FlowEventsTopic)
	if err != nil {
		return rep, err
	}
	if partPressure != nil {
		p, err := partPressure(ctx)
		if err != nil {
			return rep, fmt.Errorf("perf: flow part pressure before run: %w", err)
		}
		rep.PartsBefore = p
	}

	var insertLat Latencies
	timedStore := &timedFlowStore{Store: st, lat: &insertLat}
	consumer := pipeline.NewFlowConsumer(b, timedStore, nil, logging.New(os.Stderr, "error", "json")).
		WithTopic(topic).
		WithGroup("loadgate-flow-" + ns)
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	consumerDone := make(chan struct{})
	go func() { _ = consumer.Run(cctx); close(consumerDone) }()
	time.Sleep(150 * time.Millisecond)

	base := flowBaseTime(records)
	queryNow := base.Add(time.Duration(records+1) * time.Millisecond).Add(time.Minute)
	queryWindow := maxDuration(time.Hour, time.Duration(records+1)*time.Millisecond+3*time.Minute)

	var pubLat Latencies
	start := time.Now()
	published, batches, pubErr := publishFlowTenantBatches(cctx, b, topic, tenants, base, fullStackFlowBatchSize, &pubLat)
	rep.Published = published
	rep.Batches = batches
	if pubErr == nil {
		if f, ok := b.(bus.Flusher); ok {
			t0 := time.Now()
			pubErr = f.Flush(cctx)
			rep.FlushLatency = time.Since(t0)
		}
	}
	if pubErr != nil {
		cancel()
		<-consumerDone
		return rep, fmt.Errorf("perf: full-stack flow publish: %w", pubErr)
	}

	deadline := time.Now().Add(cfg.SettleTimeout)
	for time.Now().Before(deadline) {
		stored, _, err := confirmFlowTenants(ctx, st, tenants, queryNow, queryWindow, nil)
		if err != nil {
			cancel()
			<-consumerDone
			return rep, err
		}
		rep.Stored = stored
		if stored >= records {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	elapsed := time.Since(start)
	cancel()
	<-consumerDone

	var queryLat Latencies
	stored, mismatches, err := confirmFlowTenants(ctx, st, tenants, queryNow, queryWindow, &queryLat)
	if err != nil {
		return rep, err
	}
	rep.Stored = stored
	rep.Elapsed = elapsed
	rep.PublishLatency = pubLat.Summary()
	rep.InsertLatency = insertLat.Summary()
	rep.QueryP95 = queryLat.Summary().P95
	if elapsed > 0 {
		rep.RecordsSec = float64(rep.Stored) / elapsed.Seconds()
	}
	if bs, ok := b.(interface{ Stats() bus.PublishStats }); ok {
		st := bs.Stats()
		rep.Produced, rep.ProduceFail, rep.ProduceShed = st.Produced, st.Failed, st.Shed
	}
	rep.Rejected = consumer.RejectedBatches()
	rep.Retried = consumer.Retried()
	rep.DeadLettered = consumer.DeadLettered()
	rep.Dropped = consumer.Dropped()
	if partPressure != nil {
		p, err := partPressure(ctx)
		if err != nil {
			return rep, fmt.Errorf("perf: flow part pressure after run: %w", err)
		}
		rep.PartsAfter = p
	}

	if rep.Stored != records {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s: FLOW INGEST INCOMPLETE — %d/%d tenant-scoped rows confirmed in ClickHouse within %s",
			profile.Tier, rep.Stored, records, cfg.SettleTimeout))
	}
	rep.Violations = append(rep.Violations, mismatches...)
	if rep.Produced < uint64(rep.Published) {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s: Kafka acknowledged %d/%d flow batches", profile.Tier, rep.Produced, rep.Published))
	}
	if rep.ProduceFail > 0 || rep.ProduceShed > 0 {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s: Kafka producer loss counters non-zero: failed=%d shed=%d", profile.Tier, rep.ProduceFail, rep.ProduceShed))
	}
	if rep.Rejected > 0 || rep.DeadLettered > 0 || rep.Dropped > 0 {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s: flow consumer loss counters non-zero: rejected=%d dead_lettered=%d dropped=%d",
			profile.Tier, rep.Rejected, rep.DeadLettered, rep.Dropped))
	}
	if rep.QueryP95 > maxFlowQueryP95 {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s: flow TopTalkers query p95 %s above %s", profile.Tier, rep.QueryP95, maxFlowQueryP95))
	}
	if rep.InsertLatency.P95 > maxFlowInsertP95 {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s: ClickHouse flow insert p95 %s above %s", profile.Tier, rep.InsertLatency.P95, maxFlowInsertP95))
	}
	if rep.PartsAfter.Rows < uint64(rep.Stored) {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s: ClickHouse system.parts reports %d rows, below the %d rows confirmed by tenant queries",
			profile.Tier, rep.PartsAfter.Rows, rep.Stored))
	}
	if rep.PartsAfter.ActiveParts > rep.PartsBefore.ActiveParts+rep.MaxNewParts {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s: ClickHouse active parts grew from %d to %d (max new active parts %d) — merge pressure is not bounded",
			profile.Tier, rep.PartsBefore.ActiveParts, rep.PartsAfter.ActiveParts, rep.MaxNewParts))
	}
	return rep, nil
}

// RunFullStackFlowGate wires the REAL flow stack — Kafka plus ClickHouse — and
// drives one tier at the given scale (scale 1 = reference-hardware run).
func RunFullStackFlowGate(ctx context.Context, tier Tier, scale float64, targets FullStackFlowTargets) (FullStackFlowReport, error) {
	profile, err := ProfileFor(tier, scale)
	if err != nil {
		return FullStackFlowReport{}, err
	}
	if len(targets.Brokers) == 0 || targets.FlowStoreURL == "" {
		return FullStackFlowReport{}, fmt.Errorf("perf: full-stack flow gate needs Kafka brokers and PROBECTL_FLOWSTORE_URL")
	}
	b, err := bus.NewKafka(targets.Brokers, 0, kgo.AllowAutoTopicCreation())
	if err != nil {
		return FullStackFlowReport{}, fmt.Errorf("perf: full-stack flow kafka: %w", err)
	}
	b.WithSubscribeWorkers(max(1, min(profile.Ingest.Producers, 16)))
	defer b.Close()
	st, err := flowstore.NewClickHouse(targets.FlowStoreURL, 0)
	if err != nil {
		return FullStackFlowReport{}, fmt.Errorf("perf: full-stack flow clickhouse: %w", err)
	}
	defer st.Close()

	nonce, err := crypto.Random(4)
	if err != nil {
		return FullStackFlowReport{}, err
	}
	ns := fmt.Sprintf("lf%x", nonce)
	return DriveFullStackFlow(ctx, b, st, st.PartPressure, profile, scale < 1, ns)
}

func buildFlowTenantLoad(ns string, tenants, records int) []flowTenantLoad {
	out := make([]flowTenantLoad, 0, tenants)
	base := records / tenants
	rem := records % tenants
	for i := 0; i < tenants; i++ {
		expected := base
		if i < rem {
			expected++
		}
		out = append(out, flowTenantLoad{
			ID:       fmt.Sprintf("%s-tenant-%04d", ns, i),
			Agent:    fmt.Sprintf("flow-agent-%04d", i),
			Source:   flowSource(i),
			Exporter: flowExporter(i),
			Expected: expected,
		})
	}
	return out
}

func publishFlowTenantBatches(ctx context.Context, b bus.Bus, topic string, tenants []flowTenantLoad, base time.Time, batchSize int, lat *Latencies) (published, batches int, err error) {
	if batchSize <= 0 {
		batchSize = fullStackFlowBatchSize
	}
	var seq int64
	for i, tenant := range tenants {
		for offset := 0; offset < tenant.Expected; {
			n := min(batchSize, tenant.Expected-offset)
			batch := &flowv1.FlowBatch{Flows: make([]*flowv1.FlowRecord, n)}
			for j := 0; j < n; j++ {
				batch.Flows[j] = buildFlowRecord(tenant, i, base, seq)
				seq++
			}
			payload, merr := proto.Marshal(batch)
			if merr != nil {
				return published, batches, merr
			}
			t0 := time.Now()
			if perr := b.Publish(ctx, topic, bus.TenantKey(tenant.ID, tenant.Agent), payload); perr != nil {
				return published, batches, perr
			}
			lat.Record(time.Since(t0))
			published++
			batches++
			offset += n
		}
	}
	return published, batches, nil
}

func buildFlowRecord(tenant flowTenantLoad, tenantIdx int, base time.Time, seq int64) *flowv1.FlowRecord {
	end := base.Add(time.Duration(seq) * time.Millisecond)
	bytes := uint64(1200 + seq%900)
	packets := uint64(3 + seq%7)
	return &flowv1.FlowRecord{
		TenantId:           tenant.ID,
		AgentId:            tenant.Agent,
		ExporterAddress:    tenant.Exporter,
		ObservationDomain:  uint32(tenantIdx + 1),
		FlowProtocol:       "netflow9",
		ObservedAtUnixNano: end.Add(time.Millisecond).UnixNano(),
		StartUnixNano:      end.Add(-time.Second).UnixNano(),
		EndUnixNano:        end.UnixNano(),
		SourceAddress:      tenant.Source,
		SourcePort:         uint32(20_000 + seq%40_000),
		DestinationAddress: fmt.Sprintf("203.0.113.%d", 1+tenantIdx%250),
		DestinationPort:    443,
		NetworkTransport:   "tcp",
		NetworkType:        "ipv4",
		InputInterface:     uint32(10 + tenantIdx%64),
		OutputInterface:    uint32(20 + tenantIdx%64),
		Bytes:              bytes,
		Packets:            packets,
		SamplingRate:       1,
		BytesScaled:        bytes,
		PacketsScaled:      packets,
	}
}

func confirmFlowTenants(ctx context.Context, st flowstore.Store, tenants []flowTenantLoad, now time.Time, window time.Duration, lat *Latencies) (int, []string, error) {
	var (
		total      int
		mismatches []string
	)
	for _, tenant := range tenants {
		q := flowstore.TopQuery{TenantID: tenant.ID, By: flowstore.BySrc, Window: window, Now: now, Limit: 1}
		t0 := time.Now()
		rows, err := st.TopTalkers(ctx, q)
		if lat != nil {
			lat.Record(time.Since(t0))
		}
		if err != nil {
			return total, nil, fmt.Errorf("perf: flow TopTalkers tenant %s: %w", tenant.ID, err)
		}
		got := 0
		key := ""
		if len(rows) > 0 {
			got = int(rows[0].Flows)
			key = rows[0].Key
		}
		total += got
		if lat != nil {
			if got != tenant.Expected {
				mismatches = append(mismatches, fmt.Sprintf(
					"tenant %s confirmed %d flows, want exactly %d", tenant.ID, got, tenant.Expected))
			}
			if got > 0 && key != tenant.Source {
				mismatches = append(mismatches, fmt.Sprintf(
					"tenant %s top source %q, want %q (tenant-scoped query returned unexpected flow group)",
					tenant.ID, key, tenant.Source))
			}
		}
	}
	return total, mismatches, nil
}

func flowBaseTime(records int) time.Time {
	span := time.Duration(records+1) * time.Millisecond
	if span < time.Minute {
		span = time.Minute
	}
	return time.Now().UTC().Add(-span - time.Minute)
}

func flowSource(i int) string {
	return fmt.Sprintf("10.%d.%d.1", (i/250)%250, i%250)
}

func flowExporter(i int) string {
	return fmt.Sprintf("192.0.2.%d", 1+i%250)
}

func batchesFor(records, batchSize int) int {
	if records <= 0 {
		return 0
	}
	if batchSize <= 0 {
		batchSize = 1
	}
	return (records + batchSize - 1) / batchSize
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
