// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bus

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
)

// U-004: Publish never blocks on a degraded broker. Against an UNREACHABLE
// broker with a tiny bounded buffer, the first records are accepted
// instantly, the overflow is shed with ErrPublishShed (counted), every call
// returns fast (p99 isolated from the broker), and Close does not deadlock.
func TestAsyncPublishShedsOnUnreachableBroker(t *testing.T) {
	b, err := NewKafka([]string{"127.0.0.1:1"}, 8, // nothing listens here; tiny bound
		kgo.RetryTimeout(500*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}

	const calls = 200
	lat := make([]time.Duration, 0, calls)
	sheds := 0
	for i := 0; i < calls; i++ {
		t0 := time.Now()
		err := b.Publish(context.Background(), NetworkResultsTopic, []byte("t1"), []byte("v"))
		lat = append(lat, time.Since(t0))
		if errors.Is(err, ErrPublishShed) {
			sheds++
		} else if err != nil {
			t.Fatalf("unexpected publish error: %v", err)
		}
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p99 := lat[len(lat)*99/100-1]
	if p99 > 100*time.Millisecond {
		t.Fatalf("publish p99 = %v — the hot path is NOT isolated from the dead broker", p99)
	}
	if sheds == 0 {
		t.Fatal("a full bounded buffer must shed (no shed seen)")
	}
	st := b.Stats()
	if st.Shed == 0 || int(st.Shed) != sheds {
		t.Fatalf("shed counter = %d, want %d (drops are never silent)", st.Shed, sheds)
	}

	closed := make(chan struct{})
	go func() { _ = b.Close(); close(closed) }()
	select {
	case <-closed: // bounded flush: no deadlock on a dead broker
	case <-time.After(10 * time.Second):
		t.Fatal("Close deadlocked against a dead broker")
	}
}

// U-004: a SLOW broker (every produce delayed via kfake's control hook)
// stalls acks, not ingest — Publish p99 stays flat while records batch in
// the bounded buffer and complete asynchronously once the broker responds.
func TestAsyncPublishLatencyIsolatedFromSlowBroker(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.SeedTopics(1, NetworkResultsTopic))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	// Delay every produce request 150ms — far above the asserted publish p99.
	cluster.ControlKey(int16(kmsg.Produce), func(kmsg.Request) (kmsg.Response, error, bool) {
		time.Sleep(150 * time.Millisecond)
		return nil, nil, false // continue normal handling after the delay
	})
	cluster.KeepControl()

	b, err := NewKafka(cluster.ListenAddrs(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	const calls = 50
	lat := make([]time.Duration, 0, calls)
	for i := 0; i < calls; i++ {
		t0 := time.Now()
		if err := b.Publish(context.Background(), NetworkResultsTopic, []byte("t1"), []byte("v")); err != nil {
			t.Fatalf("publish: %v", err)
		}
		lat = append(lat, time.Since(t0))
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p99 := lat[len(lat)*99/100-1]
	if p99 > 100*time.Millisecond {
		t.Fatalf("publish p99 = %v under a 150ms-slow broker — not isolated", p99)
	}

	// The batched records complete asynchronously despite the slow broker.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if st := b.Stats(); st.Produced+st.Failed >= calls {
			if st.Produced == 0 {
				t.Fatalf("no record was acked by the slow broker: %+v", st)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("async completions never landed: %+v", b.Stats())
}

// Once Publish returns nil, the async producer owns the record. In particular,
// an HTTP request context is canceled as soon as its handler returns; that
// cancellation must not retract a record that the bus already accepted.
func TestAsyncPublishSurvivesCallerCancellationAfterAcceptance(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.SeedTopics(1, OTLPMetricsTopic))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()

	// Keep the record buffered long enough that cancel happens before franz-go
	// can send it. This makes the regression deterministic: passing the caller's
	// context directly to TryProduce drops the record during this linger window.
	b, err := NewKafka(cluster.ListenAddrs(), 0, kgo.ProducerLinger(250*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	key := []byte("tenant-a|ba")
	value := []byte("accepted-otlp-payload")
	if err := b.Publish(ctx, OTLPMetricsTopic, key, value); err != nil {
		t.Fatalf("publish: %v", err)
	}
	cancel()

	flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer flushCancel()
	if err := b.Flush(flushCtx); err != nil {
		t.Fatalf("flush accepted record: %v", err)
	}
	if got := b.Stats(); got.Produced != 1 || got.Failed != 0 || got.Buffered != 0 {
		t.Fatalf("accepted record outcome = %+v, want one broker ack and no failure", got)
	}

	consumer, err := kgo.NewClient(
		kgo.SeedBrokers(cluster.ListenAddrs()...),
		kgo.ConsumeTopics(OTLPMetricsTopic),
		kgo.ConsumeStartOffset(kgo.NewOffset().AtStart()),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	fetches := consumer.PollFetches(flushCtx)
	if errs := fetches.Errors(); len(errs) > 0 {
		t.Fatalf("consume accepted record: %v", errs)
	}
	if got := fetches.NumRecords(); got != 1 {
		t.Fatalf("consumed records = %d, want 1", got)
	}
	fetches.EachRecord(func(record *kgo.Record) {
		if record.Topic != OTLPMetricsTopic || string(record.Key) != string(key) || string(record.Value) != string(value) {
			t.Errorf("record = topic %q key %q value %q", record.Topic, record.Key, record.Value)
		}
	})
}

// Cancellation before Publish is called is not an accepted async write. It
// must fail synchronously and leave no buffered, acknowledged, or failed Kafka
// record behind.
func TestAsyncPublishRejectsPreCanceledContext(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.SeedTopics(1, OTLPMetricsTopic))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()

	b, err := NewKafka(cluster.ListenAddrs(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Publish(ctx, OTLPMetricsTopic, []byte("tenant-a|ba"), []byte("must-not-exist")); !errors.Is(err, context.Canceled) {
		t.Fatalf("publish error = %v, want context.Canceled", err)
	}
	if got := b.Stats(); got.Produced != 0 || got.Failed != 0 || got.Shed != 0 || got.Buffered != 0 {
		t.Fatalf("pre-canceled publish changed producer state: %+v", got)
	}

	consumer, err := kgo.NewClient(
		kgo.SeedBrokers(cluster.ListenAddrs()...),
		kgo.ConsumeTopics(OTLPMetricsTopic),
		kgo.ConsumeStartOffset(kgo.NewOffset().AtStart()),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	pollCtx, pollCancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer pollCancel()
	if got := consumer.PollFetches(pollCtx).NumRecords(); got != 0 {
		t.Fatalf("pre-canceled publish emitted %d Kafka record(s), want 0", got)
	}
}
