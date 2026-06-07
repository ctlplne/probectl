package pipeline

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// devFlakyWriter fails the first failN writes, then succeeds.
type devFlakyWriter struct {
	mu     sync.Mutex
	failN  int
	calls  int
	wrote  int
	failed error
}

func (w *devFlakyWriter) Write(_ context.Context, s []tsdb.Series) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	if w.calls <= w.failN {
		return errors.New("transient store outage")
	}
	if w.failed != nil {
		return w.failed
	}
	w.wrote += len(s)
	return nil
}
func (w *devFlakyWriter) Close() error { return nil }

// captureDLQBus records dead-letter publishes (and can fail them).
type captureDLQBus struct {
	mu      sync.Mutex
	dlq     []bus.Message
	failDLQ bool
}

func (b *captureDLQBus) Publish(_ context.Context, topic string, key, value []byte) error {
	if b.failDLQ {
		return errors.New("dlq broker down")
	}
	if topic != bus.DeadLetterDeviceTopic {
		return errors.New("unexpected topic " + topic)
	}
	b.mu.Lock()
	b.dlq = append(b.dlq, bus.Message{Topic: topic, Key: key, Value: value})
	b.mu.Unlock()
	return nil
}
func (b *captureDLQBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (b *captureDLQBus) Close() error                                                 { return nil }

func deviceMsg(t *testing.T, tenant, agent string) bus.Message {
	t.Helper()
	batch := &devicev1.DeviceMetricBatch{Metrics: []*devicev1.DeviceMetric{{
		TenantId: tenant, AgentId: agent, Name: "probectl.device.if.in.octets",
		Value: 1, TimeUnixNano: time.Now().UnixNano(),
	}}}
	v, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	return bus.Message{Key: []byte(tenant), Value: v}
}

// SCALE-008 residual (Sprint 14): the DEVICE plane rides the retry+DLQ
// contract — a transient store failure is RETRIED (nothing dropped, nothing
// dead-lettered); a permanent failure DEAD-LETTERS the original bytes; the
// drop counter stays 0 unless the DLQ itself is down.
func TestDeviceWriteRetryDLQOnTransientFailure(t *testing.T) {
	ctx := context.Background()

	// Transient: fails twice, third attempt lands. Drop = DLQ = 0.
	w := &devFlakyWriter{failN: 2}
	b := &captureDLQBus{}
	c := NewDeviceConsumer(b, w, testLogger())
	c.sleep = func(context.Context, time.Duration) {} // no real backoff in tests
	if err := c.handleLane(ctx, deviceMsg(t, "t-a", "agent-1"), ""); err != nil {
		t.Fatalf("handleLane: %v", err)
	}
	if w.wrote == 0 {
		t.Fatal("transient failure was not retried to success")
	}
	if got := c.retried.Load(); got != 2 {
		t.Fatalf("retried = %d, want 2", got)
	}
	if c.DeadLettered() != 0 || c.Dropped() != 0 {
		t.Fatalf("transient path must not DLQ/drop: dlq=%d dropped=%d", c.DeadLettered(), c.Dropped())
	}

	// Permanent: retries exhaust → the ORIGINAL bytes land on the device DLQ,
	// still ZERO dropped.
	w2 := &devFlakyWriter{failed: errors.New("store down hard"), failN: 0}
	w2.failed = errors.New("store down hard")
	b2 := &captureDLQBus{}
	c2 := NewDeviceConsumer(b2, w2, testLogger())
	c2.sleep = func(context.Context, time.Duration) {}
	msg := deviceMsg(t, "t-b", "agent-2")
	if err := c2.handleLane(ctx, msg, ""); err != nil {
		t.Fatalf("handleLane: %v", err)
	}
	if c2.DeadLettered() != 1 || c2.Dropped() != 0 {
		t.Fatalf("permanent failure must DLQ without dropping: dlq=%d dropped=%d", c2.DeadLettered(), c2.Dropped())
	}
	if len(b2.dlq) != 1 || string(b2.dlq[0].Value) != string(msg.Value) {
		t.Fatal("DLQ must carry the ORIGINAL message bytes (replayable)")
	}

	// Only a DLQ failure counts as a true drop — and it is loud.
	w3 := &devFlakyWriter{}
	w3.failed = errors.New("store down hard")
	b3 := &captureDLQBus{failDLQ: true}
	c3 := NewDeviceConsumer(b3, w3, testLogger())
	c3.sleep = func(context.Context, time.Duration) {}
	_ = c3.handleLane(ctx, deviceMsg(t, "t-c", "agent-3"), "")
	if c3.Dropped() != 1 {
		t.Fatalf("DLQ-down is the only true loss: dropped=%d, want 1", c3.Dropped())
	}
}
