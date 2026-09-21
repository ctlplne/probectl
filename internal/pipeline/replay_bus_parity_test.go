// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"

	"github.com/ctlplne/probectl/internal/bus"
)

// Replay parity across bus implementations (Foundation-Loop S-901480ab).
//
// The in-memory bus used to discard the consumer group, so every subscriber saw
// every message. That made replay isolation a Kafka-only property while
// lightweight mode is a shipped deployment option — and it meant the two buses
// disagreed about what a second consumer on a topic means.
//
// This suite runs ONE scenario against BOTH implementations. Each bus having
// its own replay test is how the divergence survived: two tests that never
// compare cannot disagree. kfake gives a real in-process Kafka broker, so this
// runs in plain `go test` with no JVM or Docker.

// busUnderTest names one implementation and how to build it.
type busUnderTest struct {
	name string
	// build returns the bus plus a cleanup. It may return nil to skip a bus
	// that cannot be constructed in this environment.
	build func(t *testing.T, topics ...string) bus.Bus
}

func busImplementations() []busUnderTest {
	return []busUnderTest{
		{
			name: "memory",
			build: func(t *testing.T, _ ...string) bus.Bus {
				b := bus.NewMemory()
				t.Cleanup(func() { _ = b.Close() })
				return b
			},
		},
		{
			name: "kafka",
			build: func(t *testing.T, topics ...string) bus.Bus {
				cluster, err := kfake.NewCluster(kfake.SeedTopics(1, topics...))
				if err != nil {
					t.Fatalf("kfake cluster: %v", err)
				}
				t.Cleanup(cluster.Close)
				b, err := bus.NewKafka(cluster.ListenAddrs(), 0)
				if err != nil {
					t.Fatalf("kafka bus: %v", err)
				}
				t.Cleanup(func() { _ = b.Close() })
				return b
			},
		},
	}
}

// A dead-lettered record must reappear on its source topic with the original
// tenant key and payload, exactly once per replay, on EITHER bus.
func TestDeadLetterReplayIsIdenticalOnEveryBus(t *testing.T) {
	for _, impl := range busImplementations() {
		t.Run(impl.name, func(t *testing.T) {
			b := impl.build(t, bus.DeadLetterResultsTopic, bus.NetworkResultsTopic)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			type record struct{ key, val []byte }
			captured := make(chan record, 8)
			srcCtx, srcCancel := context.WithCancel(ctx)
			defer srcCancel()
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = b.Subscribe(srcCtx, bus.NetworkResultsTopic, "parity-source", func(_ context.Context, m bus.Message) error {
					captured <- record{key: m.Key, val: m.Value}
					return nil
				})
			}()
			waitForBusSubscriber(ctx, b, bus.NetworkResultsTopic)

			// The replayer must be draining BEFORE the record is published:
			// the memory bus is a live pub/sub, so a record published to a
			// topic nobody is on is simply gone. Kafka persists and does not
			// care about the order, which is exactly why running one scenario
			// on both is the point.
			r := NewDeadLetterReplayer(b, testLogger()).WithBinding(allowAllBinding{})
			replayed := make(chan ReplayResult, 1)
			replayErr := make(chan error, 1)
			go func() {
				res, err := r.Replay(ctx, ReplayConfig{
					DLQTopic:    bus.DeadLetterResultsTopic,
					Group:       "parity-replay",
					MaxRecords:  1,
					IdleTimeout: 3 * time.Second,
				})
				if err != nil {
					replayErr <- err
					return
				}
				replayed <- res
			}()
			waitForBusSubscriber(ctx, b, bus.DeadLetterResultsTopic)

			origKey := []byte("tenant-a")
			origVal := legacyResultPayload(t, "tenant-a", "agent-1")
			if err := b.Publish(ctx, bus.DeadLetterResultsTopic, origKey, origVal); err != nil {
				t.Fatalf("seed DLQ record: %v", err)
			}
			if f, ok := b.(bus.Flusher); ok {
				if err := f.Flush(ctx); err != nil {
					t.Fatalf("flush seeded record: %v", err)
				}
			}

			var res ReplayResult
			select {
			case res = <-replayed:
			case err := <-replayErr:
				t.Fatalf("replay: %v", err)
			case <-time.After(20 * time.Second):
				t.Fatal("replay did not terminate")
			}
			if res.Replayed != 1 {
				t.Fatalf("replayed = %d, want 1", res.Replayed)
			}
			if res.SourceTopic != bus.NetworkResultsTopic {
				t.Fatalf("source topic = %q, want %q", res.SourceTopic, bus.NetworkResultsTopic)
			}

			select {
			case got := <-captured:
				if string(got.key) != "tenant-a" {
					t.Errorf("replayed key = %q, want tenant-a: the original tenant must survive the round trip", got.key)
				}
				if string(got.val) != string(origVal) {
					t.Errorf("replayed payload differs from the original bytes")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the dead-lettered record never reappeared on the source topic")
			}

			srcCancel()
			wg.Wait()
		})
	}
}

// The isolation property the memory bus could not express: a replay consumer
// group and an unrelated consumer group on the SAME DLQ topic each see the
// record, while two members of ONE group do not both see it. If a bus fans out
// to every subscriber regardless of group, the second assertion fails — which
// is precisely the state lightweight mode used to ship in.
func TestDeadLetterGroupIsolationIsIdenticalOnEveryBus(t *testing.T) {
	for _, impl := range busImplementations() {
		t.Run(impl.name, func(t *testing.T) {
			b := impl.build(t, bus.DeadLetterResultsTopic)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			subCtx, subCancel := context.WithCancel(ctx)
			defer subCancel()

			var mu sync.Mutex
			counts := map[string]int{}
			var wg sync.WaitGroup
			// Two members of "shared" must SPLIT the topic; "observer" is a
			// separate group and must receive its own copy.
			for _, s := range []struct{ label, group string }{
				{"shared-1", "shared"},
				{"shared-2", "shared"},
				{"observer", "observer"},
			} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_ = b.Subscribe(subCtx, bus.DeadLetterResultsTopic, s.group, func(context.Context, bus.Message) error {
						mu.Lock()
						counts[s.label]++
						mu.Unlock()
						return nil
					})
				}()
			}
			waitForBusSubscribers(ctx, b, bus.DeadLetterResultsTopic, 3)

			const messages = 6
			for range messages {
				if err := b.Publish(ctx, bus.DeadLetterResultsTopic, []byte("tenant-a"),
					legacyResultPayload(t, "tenant-a", "agent-1")); err != nil {
					t.Fatalf("publish: %v", err)
				}
			}
			if f, ok := b.(bus.Flusher); ok {
				if err := f.Flush(ctx); err != nil {
					t.Fatalf("flush: %v", err)
				}
			}
			// Kafka delivery is asynchronous through the broker; wait for the
			// totals to settle rather than sampling once.
			waitForCounts(ctx, &mu, counts, messages*2)

			subCancel()
			wg.Wait()

			mu.Lock()
			defer mu.Unlock()
			shared := counts["shared-1"] + counts["shared-2"]
			if shared != messages {
				t.Errorf("group %q received %d of %d messages across its members "+
					"(split %d/%d): members of ONE group must not each get a full copy",
					"shared", shared, messages, counts["shared-1"], counts["shared-2"])
			}
			if counts["observer"] != messages {
				t.Errorf("separate group received %d of %d: a distinct group must see the whole topic",
					counts["observer"], messages)
			}
		})
	}
}

// waitForBusSubscriber waits for one subscriber where the bus can report it.
func waitForBusSubscriber(ctx context.Context, b bus.Bus, topic string) {
	waitForBusSubscribers(ctx, b, topic, 1)
}

// waitForBusSubscribers synchronizes on registration where the bus exposes it
// (the memory bus is a LIVE pub/sub, so a publish before registration is lost).
// Kafka persists, so a missing implementation means "already ready".
func waitForBusSubscribers(ctx context.Context, b bus.Bus, topic string, n int) {
	if w, ok := b.(bus.SubscriberWaiter); ok {
		w.WaitForSubscribers(ctx, topic, n)
		return
	}
	// Give the Kafka group time to join before the first publish, so the test
	// measures delivery semantics rather than join latency.
	time.Sleep(2 * time.Second)
}

// waitForCounts blocks until the recorded deliveries reach want, or ctx ends.
func waitForCounts(ctx context.Context, mu *sync.Mutex, counts map[string]int, want int) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		mu.Lock()
		total := 0
		for _, n := range counts {
			total += n
		}
		mu.Unlock()
		if total >= want {
			// Let any surplus delivery (the failure this asserts against)
			// arrive before sampling, so an over-delivering bus is caught.
			time.Sleep(500 * time.Millisecond)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
