// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
)

// flowFlakyStore embeds the Store interface (so it satisfies it) but overrides
// Insert: it fails the first failN calls, then succeeds; a non-nil hardErr
// fails every call permanently. Only Insert is exercised by handleLane.
type flowFlakyStore struct {
	flowstore.Store
	mu      sync.Mutex
	failN   int
	calls   int
	wrote   int
	hardErr error
}

func (s *flowFlakyStore) Insert(_ context.Context, rows []flowstore.Row) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.hardErr != nil {
		return s.hardErr
	}
	if s.calls <= s.failN {
		return errors.New("transient store outage")
	}
	s.wrote += len(rows)
	return nil
}

// flowDLQBus records dead-letter publishes (and can fail them).
type flowDLQBus struct {
	mu      sync.Mutex
	dlq     []bus.Message
	failDLQ bool
}

func (b *flowDLQBus) Publish(_ context.Context, topic string, key, value []byte) error {
	if b.failDLQ {
		return errors.New("dlq broker down")
	}
	if topic != bus.DeadLetterFlowTopic {
		return errors.New("unexpected topic " + topic)
	}
	b.mu.Lock()
	b.dlq = append(b.dlq, bus.Message{Topic: topic, Key: key, Value: value})
	b.mu.Unlock()
	return nil
}
func (b *flowDLQBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (b *flowDLQBus) Close() error                                                 { return nil }

func flowMsg(t *testing.T, tenant, agent string) bus.Message {
	t.Helper()
	batch := &flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
		TenantId: tenant, AgentId: agent,
		SourceAddress: "10.0.0.1", DestinationAddress: "10.0.0.2",
		Bytes: 1500, Packets: 3, EndUnixNano: time.Now().UnixNano(),
	}}}
	v, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	return bus.Message{Key: []byte(tenant), Value: v}
}

// CORRECT-010 / SCALE-005: the FLOW plane now rides the same retry+DLQ contract
// as the result + device pipelines — a transient insert failure is RETRIED
// (nothing dropped, nothing dead-lettered); a permanent failure DEAD-LETTERS
// the original bytes; the drop counter only moves if the DLQ itself is down.
func TestFlowWriteRetryDLQParity(t *testing.T) {
	ctx := context.Background()

	// Transient: fails twice, third lands. DLQ = drop = 0; retried = 2.
	st := &flowFlakyStore{failN: 2}
	b := &flowDLQBus{}
	c := NewFlowConsumer(b, st, nil, testLogger())
	c.sleep = func(context.Context, time.Duration) {}
	if err := c.handleLane(ctx, flowMsg(t, "t-a", "agent-1"), ""); err != nil {
		t.Fatalf("handleLane: %v", err)
	}
	if st.wrote == 0 {
		t.Fatal("transient failure was not retried to success")
	}
	if got := c.retried.Load(); got != 2 {
		t.Fatalf("retried = %d, want 2", got)
	}
	if c.DeadLettered() != 0 || c.Dropped() != 0 {
		t.Fatalf("transient path must not DLQ/drop: dlq=%d dropped=%d", c.DeadLettered(), c.Dropped())
	}

	// Permanent: retries exhaust → ORIGINAL bytes land on the flow DLQ, drop 0.
	st2 := &flowFlakyStore{hardErr: errors.New("store down hard")}
	b2 := &flowDLQBus{}
	c2 := NewFlowConsumer(b2, st2, nil, testLogger())
	c2.sleep = func(context.Context, time.Duration) {}
	msg := flowMsg(t, "t-b", "agent-2")
	if err := c2.handleLane(ctx, msg, ""); err != nil {
		t.Fatalf("handleLane: %v", err)
	}
	if c2.DeadLettered() != 1 || c2.Dropped() != 0 {
		t.Fatalf("permanent failure must DLQ without dropping: dlq=%d dropped=%d", c2.DeadLettered(), c2.Dropped())
	}
	if len(b2.dlq) != 1 || string(b2.dlq[0].Value) != string(msg.Value) {
		t.Fatal("DLQ must carry the ORIGINAL message bytes (replayable)")
	}

	// Only a DLQ failure is a true drop.
	st3 := &flowFlakyStore{hardErr: errors.New("store down hard")}
	b3 := &flowDLQBus{failDLQ: true}
	c3 := NewFlowConsumer(b3, st3, nil, testLogger())
	c3.sleep = func(context.Context, time.Duration) {}
	_ = c3.handleLane(ctx, flowMsg(t, "t-c", "agent-3"), "")
	if c3.Dropped() != 1 {
		t.Fatalf("DLQ-down is the only true loss: dropped=%d, want 1", c3.Dropped())
	}
}

func TestFlowContextCancelUnknownOutcomeDoesNotDLQ(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	st := &flowFlakyStore{hardErr: errors.New("store returned after caller canceled")}
	b := &flowDLQBus{}
	c := NewFlowConsumer(b, st, nil, testLogger())
	c.sleep = func(context.Context, time.Duration) {}

	err := c.handleLane(ctx, flowMsg(t, "t-cancel", "agent-1"), "")
	if err == nil {
		t.Fatal("handleLane returned nil for an unknown canceled insert outcome")
	}
	if c.DeadLettered() != 0 || c.Dropped() != 0 || len(b.dlq) != 0 {
		t.Fatalf("unknown outcome must not DLQ/drop: dlq=%d dropped=%d published=%d",
			c.DeadLettered(), c.Dropped(), len(b.dlq))
	}
}

// CORRECT-015: an sFlow record carries no flow-start time (StartUnixNano == 0).
// rowFromProto must fall back to the flow's own timestamp, never stamp 1970.
func TestSFlowStartTimeFallback(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	f := &flowv1.FlowRecord{
		TenantId: "t-a", EndUnixNano: now.UnixNano(),
		Bytes: 1000, StartUnixNano: 0, // sFlow: no start time
	}
	row := rowFromProto(f)
	if row.StartTS.Year() <= 1971 {
		t.Fatalf("StartTS fell back to the epoch (%s) — sFlow zero start-time not handled", row.StartTS)
	}
	if !row.StartTS.Equal(row.TS) {
		t.Fatalf("StartTS = %s, want fallback to TS = %s", row.StartTS, row.TS)
	}
}
