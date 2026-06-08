package flow

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
)

// captureBus records every Publish for assertions.
type captureBus struct {
	topic string
	key   []byte
	value []byte
	n     int
}

func (c *captureBus) Publish(_ context.Context, topic string, key, value []byte) error {
	c.topic, c.key, c.value = topic, key, value
	c.n++
	return nil
}
func (c *captureBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (c *captureBus) Close() error                                                 { return nil }

// TestBusEmitterTenantTaggedBatch: records land on probectl.flow.events,
// tenant-keyed, as a decodable FlowBatch with sampling-scaled counters.
func TestBusEmitterTenantTaggedBatch(t *testing.T) {
	cb := &captureBus{}
	em := NewBusEmitter(cb, "t-acme")

	if err := em.Emit(context.Background(), nil); err != nil || cb.n != 0 {
		t.Fatalf("empty batch must be a no-op (n=%d err=%v)", cb.n, err)
	}

	recs := []Record{{
		TenantID: "t-acme", AgentID: "a1", Exporter: "203.0.113.1",
		Protocol: ProtoNetFlow5, Bytes: 100, Packets: 2, SamplingRate: 8,
		ObservedAt: testTime, Start: testTime, End: testTime,
	}}
	if err := em.Emit(context.Background(), recs); err != nil {
		t.Fatalf("emit: %v", err)
	}
	// The key is the bucketed tenant key (SCALE-007): tenant|bN, with the agent
	// id as entropy. Build the expected value the same way emit.go does, so this
	// asserts the keying contract instead of a stale pre-bucketing literal.
	wantKey := bus.TenantKey("t-acme", "a1")
	if cb.topic != bus.FlowEventsTopic || string(cb.key) != string(wantKey) {
		t.Fatalf("published to %q key %q (want tenant-keyed %q)", cb.topic, cb.key, wantKey)
	}
	var batch flowv1.FlowBatch
	if err := proto.Unmarshal(cb.value, &batch); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(batch.Flows) != 1 || batch.Flows[0].GetBytesScaled() != 800 || batch.Flows[0].GetTenantId() != "t-acme" {
		t.Fatalf("batch = %+v", batch.Flows)
	}
}

// TestConfigEnvOverrides: env wins over defaults, listeners toggle, validation
// catches the missing tenant.
func TestConfigEnvOverrides(t *testing.T) {
	cfg := Default()
	env := map[string]string{
		"PROBECTL_FLOW_TENANT":            "t-env",
		"PROBECTL_FLOW_BUS_MODE":          "kafka",
		"PROBECTL_FLOW_BUS_BROKERS":       "k1:9092, k2:9092",
		"PROBECTL_FLOW_SFLOW_ENABLED":     "false",
		"PROBECTL_FLOW_NETFLOW_LISTEN":    "127.0.0.1:9555",
		"PROBECTL_FLOW_BATCH_SIZE":        "42",
		"PROBECTL_FLOW_FLUSH_INTERVAL":    "5s",
		"PROBECTL_FLOW_TEMPLATE_TTL":      "1h",
		"PROBECTL_FLOW_QUEUE_SIZE":        "100",
		"PROBECTL_FLOW_WORKERS":           "4",
		"PROBECTL_FLOW_MAX_TEMPLATES":     "9",
		"PROBECTL_FLOW_READ_BUFFER_BYTES": "1024",
	}
	cfg.applyEnv(func(k string) string { return env[k] })

	if cfg.TenantID != "t-env" || cfg.Bus.Mode != "kafka" {
		t.Errorf("tenant/bus = %q/%q", cfg.TenantID, cfg.Bus.Mode)
	}
	if len(cfg.Bus.Brokers) != 2 || cfg.Bus.Brokers[1] != "k2:9092" {
		t.Errorf("brokers = %v", cfg.Bus.Brokers)
	}
	if cfg.SFlow.Enabled || !cfg.NetFlow.Enabled || cfg.NetFlow.Listen != "127.0.0.1:9555" {
		t.Errorf("listeners = %+v / %+v", cfg.NetFlow, cfg.SFlow)
	}
	if cfg.BatchSize != 42 || cfg.FlushInterval != 5*time.Second || cfg.TemplateTTL != time.Hour {
		t.Errorf("batching = %d/%v/%v", cfg.BatchSize, cfg.FlushInterval, cfg.TemplateTTL)
	}
	if cfg.QueueSize != 100 || cfg.Workers != 4 || cfg.MaxTemplates != 9 || cfg.ReadBufferBytes != 1024 {
		t.Errorf("tuning = %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("validate: %v", err)
	}

	bad := Default()
	if err := bad.Validate(); err == nil {
		t.Error("missing tenant must fail validation")
	}
}
