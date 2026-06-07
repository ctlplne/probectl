package bus

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// Kafka is a franz-go-backed Bus (pure Go, CGO-free). TLS in transit is supported
// by passing kgo.DialTLSConfig through extra options (default-on in regulated
// deploy profiles; the dev stack is plaintext). CLAUDE.md §7 guardrail 12.
//
// Publishing is ASYNC and BATCHED (U-004): records enter a BOUNDED in-flight
// buffer (DefaultMaxBuffered, tunable via Security.MaxBufferedRecords) that
// franz-go flushes in batches. Publish never blocks on the broker — ingest
// latency is isolated from broker stalls. When the broker degrades and the
// buffer fills, NEW records are SHED with ErrPublishShed (the explicit drop
// policy) and counted; async broker failures after acceptance are counted
// too. Stats() exposes produced/failed/shed/buffered — never silent.
type Kafka struct {
	producer *kgo.Client
	brokers  []string
	extra    []kgo.Opt

	produced    atomic.Uint64 // broker-acked records
	failed      atomic.Uint64 // accepted but failed after retries (async)
	shed        atomic.Uint64 // rejected at the full buffer (backpressure drop)
	maxBuffered int64

	// workers parallelizes EACH subscription's consume path (SCALE-001): a
	// poll batch is dispatched across this many key-sharded workers — records
	// sharing a key stay FIFO (per-tenant order holds), distinct keys process
	// concurrently — and the loop waits for the whole batch before polling
	// again, so commit-after-process (at-least-once) semantics are unchanged.
	// 0/1 = the previous serial behavior.
	workers int
}

// WithSubscribeWorkers sets the per-subscription parallelism (PROBECTL_BUS_WORKERS).
func (k *Kafka) WithSubscribeWorkers(n int) *Kafka { k.workers = n; return k }

// DefaultMaxBuffered bounds the async in-flight buffer (records) when no
// explicit tuning is supplied.
const DefaultMaxBuffered = 65536

// ErrPublishShed is returned when the bounded in-flight buffer is full (the
// broker is degraded/unreachable): the record was DROPPED, the drop was
// counted, and the caller did not block.
var ErrPublishShed = errors.New("bus: in-flight buffer full — record shed (broker degraded; see Stats)")

// PublishStats are the producer's cumulative counters.
type PublishStats struct {
	Produced uint64 // broker-acked
	Failed   uint64 // accepted, failed asynchronously after retries
	Shed     uint64 // dropped at the full buffer
	Buffered int64  // currently in flight
}

// NewKafka creates a Kafka bus seeded with brokers. The async producer is
// bounded and batched; maxBuffered bounds the in-flight buffer (<=0 uses
// DefaultMaxBuffered).
func NewKafka(brokers []string, maxBuffered int, extra ...kgo.Opt) (*Kafka, error) {
	if maxBuffered <= 0 {
		maxBuffered = DefaultMaxBuffered
	}
	opts := append([]kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.MaxBufferedRecords(maxBuffered),
		kgo.ProducerLinger(5 * time.Millisecond), // micro-batching on the hot path
	}, extra...)
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("bus: kafka producer: %w", err)
	}
	return &Kafka{producer: cl, brokers: brokers, extra: extra, maxBuffered: int64(maxBuffered)}, nil
}

// Publish enqueues value for topic, keyed by key, and returns WITHOUT waiting
// for the broker (U-004). nil means "accepted into the bounded buffer";
// ErrPublishShed means the buffer is full and the record was dropped+counted.
// Async outcomes land in Stats.
func (k *Kafka) Publish(ctx context.Context, topic string, key, value []byte) error {
	// Shed BEFORE buffering when the bound is reached: the check races
	// concurrent publishers by a handful of records at most, and kgo's own
	// MaxBufferedRecords stays the hard bound underneath (its ErrMaxBuffered
	// completions are counted as sheds too, asynchronously).
	if k.producer.BufferedProduceRecords() >= k.maxBuffered {
		k.shed.Add(1)
		return ErrPublishShed
	}
	k.producer.TryProduce(ctx, &kgo.Record{Topic: topic, Key: key, Value: value}, func(_ *kgo.Record, err error) {
		switch {
		case err == nil:
			k.produced.Add(1)
		case errors.Is(err, kgo.ErrMaxBuffered):
			k.shed.Add(1) // lost the race for the last slot — still a counted shed
		default:
			k.failed.Add(1) // accepted, failed after the client's retries
		}
	})
	return nil
}

// Stats reports the cumulative async-producer counters.
func (k *Kafka) Stats() PublishStats {
	return PublishStats{
		Produced: k.produced.Load(),
		Failed:   k.failed.Load(),
		Shed:     k.shed.Load(),
		Buffered: k.producer.BufferedProduceRecords(),
	}
}

// Subscribe consumes topic in a consumer group until ctx is canceled. franz-go
// auto-commits offsets, so delivery is at-least-once.
func (k *Kafka) Subscribe(ctx context.Context, topic, group string, handler Handler) error {
	opts := append([]kgo.Opt{
		kgo.SeedBrokers(k.brokers...),
		kgo.ConsumerGroup(group),
		kgo.ConsumeTopics(topic),
		// A brand-new group reads from the start so no buffered results are lost;
		// an established group resumes from its committed offset.
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	}, k.extra...)
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return fmt.Errorf("bus: kafka consumer: %w", err)
	}
	defer cl.Close()

	for ctx.Err() == nil {
		fetches := cl.PollFetches(ctx)
		if fetches.IsClientClosed() {
			return nil
		}
		if k.workers <= 1 {
			fetches.EachRecord(func(r *kgo.Record) {
				_ = handler(ctx, Message{Topic: r.Topic, Key: r.Key, Value: r.Value})
			})
			continue
		}
		// SCALE-001: shard the poll batch by key across bounded workers; wait
		// for the batch so offsets never run ahead of processing.
		shards := make([][]Message, k.workers)
		fetches.EachRecord(func(r *kgo.Record) {
			i := int(shardKey(r.Key)) % k.workers
			shards[i] = append(shards[i], Message{Topic: r.Topic, Key: r.Key, Value: r.Value})
		})
		var wg sync.WaitGroup
		for _, shard := range shards {
			if len(shard) == 0 {
				continue
			}
			wg.Add(1)
			go func(ms []Message) {
				defer wg.Done()
				for _, m := range ms {
					_ = handler(ctx, m)
				}
			}(shard)
		}
		wg.Wait()
	}
	return nil
}

// Close drains the in-flight buffer (bounded by a flush timeout — shutdown
// never hangs on a dead broker) and closes the producer.
func (k *Kafka) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = k.producer.Flush(ctx) // best-effort drain; unflushed records are already counted
	k.producer.Close()
	return nil
}

// shardKey hashes a record key onto a worker shard (FNV-1a). An empty key
// hashes to one shard — key-less topics keep global order (the conservative
// choice; key your records to parallelize them).
func shardKey(key []byte) uint32 {
	var h uint32 = 2166136261
	for _, b := range key {
		h ^= uint32(b)
		h *= 16777619
	}
	return h
}
