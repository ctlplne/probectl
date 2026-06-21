// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/metrics"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// otlpFailWriter always fails the store write (forces the retry + DLQ path).
type otlpFailWriter struct{ writes int }

func (w *otlpFailWriter) Write(context.Context, []tsdb.Series) error {
	w.writes++
	return errors.New("store down")
}
func (w *otlpFailWriter) Close() error { return nil }

// otlpDLQBus records DLQ publishes (Subscribe unused — tests drive handle()).
type otlpDLQBus struct {
	mu        sync.Mutex
	published []bus.Message
	failPub   bool
}

func (b *otlpDLQBus) Publish(_ context.Context, topic string, key, value []byte) error {
	if b.failPub {
		return errors.New("dlq down")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.published = append(b.published, bus.Message{Topic: topic, Key: key, Value: value})
	return nil
}
func (b *otlpDLQBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (b *otlpDLQBus) Close() error                                                 { return nil }

func oneGaugeRequest(tenant string) []byte {
	rm := &metricspb.ResourceMetrics{
		ScopeMetrics: []*metricspb.ScopeMetrics{{
			Metrics: []*metricspb.Metric{{Name: "m", Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{
				DataPoints: []*metricspb.NumberDataPoint{{Value: &metricspb.NumberDataPoint_AsInt{AsInt: 1}}},
			}}}},
		}},
	}
	if tenant != "" {
		rm.Resource = &resourcepb.Resource{Attributes: []*commonpb.KeyValue{kv("probectl.tenant.id", tenant)}}
	}
	payload, _ := proto.Marshal(&colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{rm}})
	return payload
}

// SCALE-003 / ARCH-002: a store-write failure is RETRIED then dead-lettered
// (original bytes, replayable) and counted — never a silent best-effort drop.
func TestOTLPMetricsDeadLettersOnStoreFailure(t *testing.T) {
	dlqBus := &otlpDLQBus{}
	reg := metrics.New("test", "abc")
	c := NewOTLPConsumer(dlqBus, &otlpFailWriter{}, testLogger()).WithMetrics(reg)
	c.dlq.sleep = func(context.Context, time.Duration) {} // no real backoff in tests

	payload := oneGaugeRequest("t-dlq")
	key := bus.TenantKey("t-dlq", "a")
	if err := c.handle(context.Background(), bus.Message{Key: key, Value: payload}); err != nil {
		t.Fatalf("handle must not error the stream: %v", err)
	}

	if c.Consumed() != 0 {
		t.Fatalf("consumed = %d, want 0 (store failed)", c.Consumed())
	}
	if st := c.dlq.stats(); st.DeadLettered != 1 || st.Dropped != 0 || st.Retried == 0 {
		t.Fatalf("dlq stats = %+v, want 1 dead-lettered, 0 dropped, >0 retried", st)
	}
	if len(dlqBus.published) != 1 || dlqBus.published[0].Topic != bus.DeadLetterOTLPMetricsTopic {
		t.Fatalf("expected one publish to %s, got %+v", bus.DeadLetterOTLPMetricsTopic, dlqBus.published)
	}
	if string(dlqBus.published[0].Value) != string(payload) {
		t.Fatal("dead-letter must carry the ORIGINAL bytes (replayable)")
	}
	if string(dlqBus.published[0].Key) != string(key) {
		t.Fatal("dead-letter must preserve the tenant key")
	}
	// Surfaced at /metrics.
	if reg.Counter("probectl_otlp_metrics_dead_lettered_total", "").Value() != 1 {
		t.Fatal("dead-letter counter must be surfaced in the metrics registry")
	}
}

// When the DLQ publish ALSO fails, the loss is counted as a drop (true loss).
func TestOTLPMetricsDropWhenDLQAlsoFails(t *testing.T) {
	c := NewOTLPConsumer(&otlpDLQBus{failPub: true}, &otlpFailWriter{}, testLogger())
	c.dlq.sleep = func(context.Context, time.Duration) {}
	if err := c.handle(context.Background(), bus.Message{Key: bus.TenantKey("t", "a"), Value: oneGaugeRequest("")}); err != nil {
		t.Fatalf("handle must not error the stream: %v", err)
	}
	if st := c.dlq.stats(); st.Dropped != 1 || st.DeadLettered != 0 {
		t.Fatalf("dlq stats = %+v, want 1 dropped (DLQ publish failed)", st)
	}
}

func TestOTLPMetricsContextCancelUnknownOutcomeDoesNotDLQ(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	dlqBus := &otlpDLQBus{}
	c := NewOTLPConsumer(dlqBus, &otlpFailWriter{}, testLogger())
	c.dlq.sleep = func(context.Context, time.Duration) {}

	err := c.handle(ctx, bus.Message{Key: bus.TenantKey("t-cancel", "a"), Value: oneGaugeRequest("t-cancel")})
	if err == nil {
		t.Fatal("handle returned nil for an unknown canceled OTLP write outcome")
	}
	if st := c.dlq.stats(); st.DeadLettered != 0 || st.Dropped != 0 || len(dlqBus.published) != 0 {
		t.Fatalf("unknown outcome must not DLQ/drop: stats=%+v published=%d", st, len(dlqBus.published))
	}
}

func TestOTLPDLQAccountsEverySignal(t *testing.T) {
	for _, tc := range []struct {
		signal       string
		dlqTopic     string
		ledgerSignal string
	}{
		{signal: "metrics", dlqTopic: bus.DeadLetterOTLPMetricsTopic, ledgerSignal: "otlp_metrics"},
		{signal: "traces", dlqTopic: bus.DeadLetterOTLPTracesTopic, ledgerSignal: "otlp_traces"},
		{signal: "logs", dlqTopic: bus.DeadLetterOTLPLogsTopic, ledgerSignal: "otlp_logs"},
	} {
		t.Run(tc.signal, func(t *testing.T) {
			reg := metrics.New("test", "abc")
			ledger := newIntegrityLedger(tc.ledgerSignal)
			ledger.withMetrics(reg)
			dlqBus := &otlpDLQBus{}
			dlq := newOTLPDLQ(dlqBus, tc.dlqTopic, tc.signal, testLogger(), ledger)
			dlq.withMetrics(reg)
			dlq.maxRetries = 1
			dlq.sleep = func(context.Context, time.Duration) {}

			msg := bus.Message{Key: bus.TenantKey("tenant-"+tc.signal, "agent-a"), Value: []byte("original-" + tc.signal)}
			attempts := 0
			stored, err := dlq.process(context.Background(), msg, func(context.Context) error {
				attempts++
				return errors.New("store down")
			})
			if err != nil {
				t.Fatalf("dead-lettered store failure must be handled: %v", err)
			}
			if stored {
				t.Fatal("stored = true after permanent store failure")
			}
			if attempts != 2 {
				t.Fatalf("write attempts = %d, want 2 (initial + one bounded retry)", attempts)
			}
			if st := dlq.stats(); st.Retried != 1 || st.DeadLettered != 1 || st.Dropped != 0 {
				t.Fatalf("dlq stats = %+v, want retried=1 dead-lettered=1 dropped=0", st)
			}
			if st := ledger.stats(); st.DeadLettered != 1 || st.Dropped != 0 {
				t.Fatalf("ledger stats = %+v, want dead-lettered=1 dropped=0", st)
			}
			if got := reg.Counter("probectl_otlp_"+tc.signal+"_dead_lettered_total", "").Value(); got != 1 {
				t.Fatalf("dead-letter counter = %d, want 1", got)
			}
			if got := reg.Counter("probectl_pipeline_"+tc.ledgerSignal+"_dead_lettered_total", "").Value(); got != 1 {
				t.Fatalf("pipeline dead-letter counter = %d, want 1", got)
			}
			if len(dlqBus.published) != 1 {
				t.Fatalf("published DLQ messages = %d, want 1", len(dlqBus.published))
			}
			got := dlqBus.published[0]
			if got.Topic != tc.dlqTopic || string(got.Key) != string(msg.Key) || string(got.Value) != string(msg.Value) {
				t.Fatalf("dead-letter must preserve topic/key/original bytes: got %+v want topic=%s key=%q value=%q",
					got, tc.dlqTopic, string(msg.Key), string(msg.Value))
			}

			dropReg := metrics.New("test", "abc")
			dropLedger := newIntegrityLedger(tc.ledgerSignal)
			dropLedger.withMetrics(dropReg)
			dropDLQ := newOTLPDLQ(&otlpDLQBus{failPub: true}, tc.dlqTopic, tc.signal, testLogger(), dropLedger)
			dropDLQ.withMetrics(dropReg)
			dropDLQ.maxRetries = 0
			dropDLQ.sleep = func(context.Context, time.Duration) {}

			stored, err = dropDLQ.process(context.Background(), msg, func(context.Context) error {
				return errors.New("store down")
			})
			if err != nil {
				t.Fatalf("counted drop must be handled: %v", err)
			}
			if stored {
				t.Fatal("stored = true after store+DLQ failure")
			}
			if st := dropDLQ.stats(); st.DeadLettered != 0 || st.Dropped != 1 {
				t.Fatalf("drop dlq stats = %+v, want dead-lettered=0 dropped=1", st)
			}
			if st := dropLedger.stats(); st.DeadLettered != 0 || st.Dropped != 1 {
				t.Fatalf("drop ledger stats = %+v, want dead-lettered=0 dropped=1", st)
			}
			if got := dropReg.Counter("probectl_otlp_"+tc.signal+"_dropped_total", "").Value(); got != 1 {
				t.Fatalf("drop counter = %d, want 1", got)
			}
			if got := dropReg.Counter("probectl_pipeline_"+tc.ledgerSignal+"_dropped_total", "").Value(); got != 1 {
				t.Fatalf("pipeline drop counter = %d, want 1", got)
			}
		})
	}
}
