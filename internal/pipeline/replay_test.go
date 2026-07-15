// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package pipeline

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"

	"github.com/imfeelingtheagi/probectl/internal/bus"
)

// TestDeadLetterReplayReingests is the ARCH-001 acceptance test: a record
// parked on probectl.deadletter.results is, after a replay, re-published to the
// source topic (probectl.network.results) with its ORIGINAL tenant key and
// payload — proving the product can recover dead-lettered telemetry itself.
func TestDeadLetterReplayReingests(t *testing.T) {
	b := bus.NewMemory()
	defer b.Close()

	// A subscriber on the SOURCE topic captures what the replay re-ingests.
	type got struct {
		key, val []byte
	}
	captured := make(chan got, 4)
	srcCtx, srcCancel := context.WithCancel(context.Background())
	defer srcCancel()
	var srcWG sync.WaitGroup
	srcWG.Add(1)
	go func() {
		defer srcWG.Done()
		_ = b.Subscribe(srcCtx, bus.NetworkResultsTopic, "test-source", func(_ context.Context, m bus.Message) error {
			captured <- got{key: m.Key, val: m.Value}
			return nil
		})
	}()

	// Start the replayer draining the DLQ topic.
	r := NewDeadLetterReplayer(b, testLogger())
	replayDone := make(chan ReplayResult, 1)
	go func() {
		res, err := r.Replay(context.Background(), ReplayConfig{
			DLQTopic:    bus.DeadLetterResultsTopic,
			IdleTimeout: 300 * time.Millisecond,
		})
		if err != nil {
			t.Errorf("replay: %v", err)
		}
		replayDone <- res
	}()

	// Give both subscribers a moment to register, then dead-letter a record.
	time.Sleep(50 * time.Millisecond)
	origKey := []byte("tenant-a")
	origVal := []byte("the-original-result-bytes")
	if err := b.Publish(context.Background(), bus.DeadLetterResultsTopic, origKey, origVal); err != nil {
		t.Fatal(err)
	}

	// The record must reappear on the source topic, verbatim.
	select {
	case g := <-captured:
		if string(g.key) != "tenant-a" {
			t.Errorf("replayed key = %q, want tenant-a (original tenant must be preserved)", g.key)
		}
		if string(g.val) != "the-original-result-bytes" {
			t.Errorf("replayed payload = %q, want the original bytes", g.val)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out: replay did not re-ingest the dead-lettered record onto the source topic")
	}

	// The replayer terminates on idle and reports the count.
	select {
	case res := <-replayDone:
		if res.Replayed != 1 {
			t.Errorf("replayed count = %d, want 1", res.Replayed)
		}
		if res.SourceTopic != bus.NetworkResultsTopic {
			t.Errorf("source topic = %q, want %q", res.SourceTopic, bus.NetworkResultsTopic)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("replay did not terminate on idle")
	}
}

func TestDeadLetterReplayFlushFailurePreventsCommit(t *testing.T) {
	flushErr := errors.New("broker flush failed")
	b := &flushFailReplayBus{
		msg:      bus.Message{Topic: bus.DeadLetterResultsTopic, Key: []byte("tenant-a"), Value: []byte("payload")},
		flushErr: flushErr,
	}

	r := NewDeadLetterReplayer(b, testLogger())
	res, err := r.Replay(context.Background(), ReplayConfig{
		DLQTopic:    bus.DeadLetterResultsTopic,
		IdleTimeout: time.Second,
	})
	if !errors.Is(err, flushErr) {
		t.Fatalf("Replay error = %v, want flush failure", err)
	}
	if res.Replayed != 0 {
		t.Fatalf("replayed count after flush failure = %d, want 0", res.Replayed)
	}
	if !b.published {
		t.Fatal("test setup failed: replay did not publish to source before flush")
	}
	if b.committed {
		t.Fatal("DLQ record was committed even though source publish was not durable")
	}
}

func TestDeadLetterReplayKafkaFlushFailureLeavesDLQRedeliverable(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.SeedTopics(1, bus.DeadLetterResultsTopic, bus.NetworkResultsTopic))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()

	seed, err := bus.NewKafka(cluster.ListenAddrs(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := seed.Publish(ctx, bus.DeadLetterResultsTopic, []byte("tenant-a"), []byte("payload")); err != nil {
		t.Fatalf("seed DLQ record: %v", err)
	}
	if err := seed.Flush(ctx); err != nil {
		t.Fatalf("flush seeded DLQ record: %v", err)
	}

	k1, err := bus.NewKafka(cluster.ListenAddrs(), 0)
	if err != nil {
		t.Fatal(err)
	}
	failing := &flushFailKafkaBus{Kafka: k1, err: errors.New("forced source flush failure")}
	r1 := NewDeadLetterReplayer(failing, testLogger())
	res, err := r1.Replay(ctx, ReplayConfig{
		DLQTopic:    bus.DeadLetterResultsTopic,
		Group:       "spine-002-redelivery",
		IdleTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("first replay with failing flush: %v", err)
	}
	if failing.flushes.Load() == 0 {
		t.Fatal("test setup failed: replay did not reach the source flush barrier")
	}
	if res.Replayed != 0 {
		t.Fatalf("replayed count after failed Kafka flush = %d, want 0", res.Replayed)
	}
	if got := failing.Stats().HandlerErrors; got == 0 {
		t.Fatal("Kafka handler error counter stayed zero; DLQ offset may have been marked despite flush failure")
	}
	if err := failing.Close(); err != nil {
		t.Fatalf("close failing bus: %v", err)
	}

	k2, err := bus.NewKafka(cluster.ListenAddrs(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer k2.Close()
	r2 := NewDeadLetterReplayer(k2, testLogger())
	res, err = r2.Replay(ctx, ReplayConfig{
		DLQTopic:    bus.DeadLetterResultsTopic,
		Group:       "spine-002-redelivery",
		MaxRecords:  1,
		IdleTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("second replay after failed flush: %v", err)
	}
	if res.Replayed != 1 {
		t.Fatalf("redelivered replay count = %d, want 1", res.Replayed)
	}
}

// TestDeadLetterReplayRejectsUnknownTopic: a non-DLQ topic fails closed.
func TestDeadLetterReplayRejectsUnknownTopic(t *testing.T) {
	r := NewDeadLetterReplayer(bus.NewMemory(), testLogger())
	if _, err := r.Replay(context.Background(), ReplayConfig{DLQTopic: "probectl.network.results"}); err == nil {
		t.Fatal("replay must reject a topic that is not a dead-letter topic")
	}
}

type flushFailReplayBus struct {
	msg       bus.Message
	flushErr  error
	published bool
	committed bool
}

func (b *flushFailReplayBus) Publish(_ context.Context, topic string, key, value []byte) error {
	b.published = topic == bus.NetworkResultsTopic && string(key) == "tenant-a" && string(value) == "payload"
	return nil
}

func (b *flushFailReplayBus) Subscribe(ctx context.Context, _ string, _ string, handler bus.Handler) error {
	err := handler(ctx, b.msg)
	if err == nil {
		b.committed = true
	}
	return err
}

func (b *flushFailReplayBus) Flush(context.Context) error { return b.flushErr }

func (b *flushFailReplayBus) Close() error { return nil }

type flushFailKafkaBus struct {
	*bus.Kafka
	err     error
	flushes atomic.Uint64
}

func (b *flushFailKafkaBus) Flush(context.Context) error {
	b.flushes.Add(1)
	return b.err
}

// TestReplaySourceMapping pins every DLQ topic to its source.
func TestReplaySourceMapping(t *testing.T) {
	cases := map[string]string{
		bus.DeadLetterResultsTopic:     bus.NetworkResultsTopic,
		bus.DeadLetterDeviceTopic:      bus.DeviceMetricsTopic,
		bus.DeadLetterFlowTopic:        bus.FlowEventsTopic,
		bus.DeadLetterOTLPMetricsTopic: bus.OTLPMetricsTopic,
		bus.DeadLetterOTLPTracesTopic:  bus.OTLPTracesTopic,
		bus.DeadLetterOTLPLogsTopic:    bus.OTLPLogsTopic,
	}
	for dlq, want := range cases {
		got, ok := SourceTopicFor(dlq)
		if !ok || got != want {
			t.Errorf("SourceTopicFor(%q) = %q,%v; want %q", dlq, got, ok, want)
		}
	}
}
