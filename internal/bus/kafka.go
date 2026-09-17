// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bus

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
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
	handlerErr  atomic.Uint64 // consumed records whose handler returned an error (NOT committed → redelivered)
	maxBuffered int64

	// DPR-141: the consumer's own view of how far behind it is, taken from the
	// high watermarks that every fetch response already carries.
	lagMax         atomic.Int64
	lagAssignments atomic.Int64
	lagSeen        atomic.Bool

	// workers parallelizes EACH subscription's consume path (SCALE-001): a
	// poll batch is dispatched across this many key-sharded workers — records
	// sharing a key stay FIFO (per-tenant order holds), distinct keys process
	// concurrently — and the loop waits for the whole batch before polling
	// again, so commit-after-process (at-least-once) semantics are unchanged.
	// 0/1 = the previous serial behavior.
	workers int

	// consumeFromEnd is a test/harness-only mode for consumers that publish and
	// measure a fresh namespace on a shared topic. Production defaults to
	// AtStart so a brand-new group never skips buffered telemetry.
	consumeFromEnd bool

	// lastFailure is the most recent asynchronous produce failure (DPR-047).
	// Flush only sees "context deadline exceeded" when records cannot be
	// delivered; the underlying broker reason (unknown topic, authorization,
	// ...) lives here so the operator-facing error can name it.
	lastFailure atomic.Pointer[produceFailure]
}

type produceFailure struct {
	topic string
	err   error
}

// WithSubscribeWorkers sets the per-subscription parallelism (PROBECTL_BUS_WORKERS).
func (k *Kafka) WithSubscribeWorkers(n int) *Kafka { k.workers = n; return k }

// WithSubscribeFromEnd makes newly-created consumer groups start at the latest
// topic offset. Use only for harnesses that intentionally ignore old topic
// contents; production pipelines should keep the default AtStart behavior.
func (k *Kafka) WithSubscribeFromEnd() *Kafka { k.consumeFromEnd = true; return k }

// DefaultMaxBuffered bounds the async in-flight buffer (records) when no
// explicit tuning is supplied.
const DefaultMaxBuffered = 65536

// ErrPublishShed is returned when the bounded in-flight buffer is full (the
// broker is degraded/unreachable): the record was DROPPED, the drop was
// counted, and the caller did not block.
var ErrPublishShed = errors.New("bus: in-flight buffer full — record shed (broker degraded; see Stats)")

// PublishStats are the bus's cumulative counters (producer + consumer).
type PublishStats struct {
	Produced      uint64 // broker-acked
	Failed        uint64 // accepted, failed asynchronously after retries
	Shed          uint64 // dropped at the full buffer
	Buffered      int64  // currently in flight
	HandlerErrors uint64 // consumed records whose handler errored (offset NOT committed → redelivered)
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
		// DPR-047: ask brokers that permit auto-creation to create a lane on
		// first use; brokers that do not are covered by EnsureTopics at startup.
		kgo.AllowAutoTopicCreation(),
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
	if ctx == nil {
		ctx = context.Background()
	}
	// A context canceled before Publish starts means the caller withdrew the
	// write, so reject it synchronously. Once this check passes and the record is
	// accepted, the async Kafka client owns delivery: an HTTP/gRPC request
	// context is canceled as soon as its handler returns, which must not revoke a
	// record after Publish has already returned nil. The bounded producer buffer
	// caps retained work, Flush remains the explicit durability barrier, and the
	// client lifecycle/Close still terminates detached delivery.
	if err := ctx.Err(); err != nil {
		return err
	}
	// Shed BEFORE buffering when the bound is reached: the check races
	// concurrent publishers by a handful of records at most, and kgo's own
	// MaxBufferedRecords stays the hard bound underneath (its ErrMaxBuffered
	// completions are counted as sheds too, asynchronously).
	if k.producer.BufferedProduceRecords() >= k.maxBuffered {
		k.shed.Add(1)
		return ErrPublishShed
	}
	k.producer.TryProduce(context.WithoutCancel(ctx), &kgo.Record{Topic: topic, Key: key, Value: value}, func(_ *kgo.Record, err error) {
		switch {
		case err == nil:
			k.produced.Add(1)
		case errors.Is(err, kgo.ErrMaxBuffered):
			k.shed.Add(1) // lost the race for the last slot — still a counted shed
		default:
			k.failed.Add(1) // accepted, failed after the client's retries
			k.recordFailure(topic, err)
		}
	})
	return nil
}

// PublishFailures implements PublishFailureReporter: accepted-but-undelivered
// records (failed after retries / shed at the full buffer) and the last
// asynchronous produce error, so a producer can surface what Publish's nil
// return hid (DPR-071).
func (k *Kafka) PublishFailures() (failed, shed uint64, last error) {
	if f := k.lastFailure.Load(); f != nil {
		last = fmt.Errorf("last produce failure on %s: %w", f.topic, f.err)
	}
	return k.failed.Load(), k.shed.Load(), last
}

// Stats reports the cumulative async-producer counters.
func (k *Kafka) Stats() PublishStats {
	return PublishStats{
		Produced:      k.produced.Load(),
		Failed:        k.failed.Load(),
		Shed:          k.shed.Load(),
		Buffered:      k.producer.BufferedProduceRecords(),
		HandlerErrors: k.handlerErr.Load(),
	}
}

// Flush blocks until every record buffered by Publish has been acknowledged by
// the broker (or the context expires), returning ctx.Err() on timeout. It is
// how a caller converts the async, fire-and-forget Publish into a durability
// barrier: the agent transport flushes a result batch here BEFORE it acks the
// agent, so a result is only acked once it is broker-durable (CORRECT-004) —
// never acked-then-lost in the in-flight buffer if the process dies.
func (k *Kafka) Flush(ctx context.Context) error {
	return k.flushError(k.producer.Flush(ctx))
}

// flushError decorates a failed flush with the last asynchronous produce
// failure, so "context deadline exceeded" is never the whole story.
func (k *Kafka) flushError(err error) error {
	if err == nil {
		return nil
	}
	if f := k.lastFailure.Load(); f != nil {
		return fmt.Errorf("%w (last produce failure on %s: %v)", err, f.topic, f.err)
	}
	return err
}

func (k *Kafka) recordFailure(topic string, err error) {
	k.lastFailure.Store(&produceFailure{topic: topic, err: err})
}

// TopicsMissing returns the subset of topics the brokers do not know
// (DPR-047). It never creates anything.
func (k *Kafka) TopicsMissing(ctx context.Context, topics []string) ([]string, error) {
	if len(topics) == 0 {
		return nil, nil
	}
	req := kmsg.NewPtrMetadataRequest()
	req.AllowAutoTopicCreation = false
	for _, t := range topics {
		topic := kmsg.NewMetadataRequestTopic()
		name := t
		topic.Topic = &name
		req.Topics = append(req.Topics, topic)
	}
	resp, err := req.RequestWith(ctx, k.producer)
	if err != nil {
		return nil, fmt.Errorf("bus: kafka metadata: %w", err)
	}
	var missing []string
	for _, t := range resp.Topics {
		if t.Topic == nil {
			continue
		}
		if kerr.ErrorForCode(t.ErrorCode) != nil {
			missing = append(missing, *t.Topic)
		}
	}
	sort.Strings(missing)
	return missing, nil
}

// EnsureTopics creates the given topics when they are missing (DPR-047):
// partitions per topic, replication -1 for the broker default. It returns the
// topics it created; TOPIC_ALREADY_EXISTS is not an error. Any other broker
// refusal (authorization, invalid replication) is returned so the plane can
// fail closed with the reason instead of refusing every result batch later.
func (k *Kafka) EnsureTopics(ctx context.Context, topics []string, partitions int32, replication int16) ([]string, error) {
	missing, err := k.TopicsMissing(ctx, topics)
	if err != nil {
		return nil, err
	}
	if len(missing) == 0 {
		return nil, nil
	}
	if partitions <= 0 {
		partitions = 1
	}
	if replication == 0 {
		replication = -1
	}
	req := kmsg.NewPtrCreateTopicsRequest()
	req.TimeoutMillis = 15000
	for _, t := range missing {
		topic := kmsg.NewCreateTopicsRequestTopic()
		topic.Topic = t
		topic.NumPartitions = partitions
		topic.ReplicationFactor = replication
		req.Topics = append(req.Topics, topic)
	}
	resp, err := req.RequestWith(ctx, k.producer)
	if err != nil {
		return nil, fmt.Errorf("bus: kafka create topics: %w", err)
	}
	var created []string
	for _, t := range resp.Topics {
		switch e := kerr.ErrorForCode(t.ErrorCode); {
		case e == nil:
			created = append(created, t.Topic)
		case errors.Is(e, kerr.TopicAlreadyExists):
		default:
			msg := e.Error()
			if t.ErrorMessage != nil && *t.ErrorMessage != "" {
				msg = *t.ErrorMessage
			}
			return created, fmt.Errorf("bus: kafka refused to create topic %s: %s", t.Topic, msg)
		}
	}
	sort.Strings(created)
	return created, nil
}

// ListEmptyGroups returns the consumer groups the brokers report with no
// members — nobody is consuming them (DPR-109). A group whose state the broker
// does not report is never included: an old broker that answers ListGroups
// without a state must not be read as "everything is abandoned".
func (k *Kafka) ListEmptyGroups(ctx context.Context) ([]string, error) {
	req := kmsg.NewPtrListGroupsRequest()
	req.StatesFilter = []string{"Empty", "Dead"}
	resp, err := req.RequestWith(ctx, k.producer)
	if err != nil {
		return nil, fmt.Errorf("bus: kafka list groups: %w", err)
	}
	if e := kerr.ErrorForCode(resp.ErrorCode); e != nil {
		return nil, fmt.Errorf("bus: kafka list groups: %w", e)
	}
	var empty []string
	for _, g := range resp.Groups {
		switch strings.ToLower(g.GroupState) {
		case "empty", "dead":
			empty = append(empty, g.Group)
		}
	}
	sort.Strings(empty)
	return empty, nil
}

// DeleteGroups removes consumer groups and the committed offsets they hold,
// returning the ones actually deleted. A group that is no longer there, or that
// gained a member since it was listed, is not an error — the next sweep sees it
// again. Any other refusal (authorization) is returned so the caller can say so
// once instead of retrying blindly.
func (k *Kafka) DeleteGroups(ctx context.Context, groups []string) ([]string, error) {
	if len(groups) == 0 {
		return nil, nil
	}
	req := kmsg.NewPtrDeleteGroupsRequest()
	req.Groups = append(req.Groups, groups...)
	resp, err := req.RequestWith(ctx, k.producer)
	if err != nil {
		return nil, fmt.Errorf("bus: kafka delete groups: %w", err)
	}
	var deleted []string
	var refused error
	for _, g := range resp.Groups {
		switch e := kerr.ErrorForCode(g.ErrorCode); {
		case e == nil:
			deleted = append(deleted, g.Group)
		case errors.Is(e, kerr.GroupIDNotFound), errors.Is(e, kerr.NonEmptyGroup):
		default:
			if refused == nil {
				refused = fmt.Errorf("bus: kafka refused to delete group %s: %w", g.Group, e)
			}
		}
	}
	sort.Strings(deleted)
	return deleted, refused
}

// Subscribe consumes topic in a consumer group until ctx is canceled.
//
// Delivery is TRUE at-least-once (SCALE-007): the previous code relied on
// franz-go's periodic auto-commit, which advances offsets on a TIMER regardless
// of whether the handler ran — a crash between an auto-commit and the handler
// silently lost those records, so the "at-least-once" claim was false. We now
// use AutoCommitMarks: nothing commits until it is MARKED, and a record is
// marked ONLY after its handler returns nil. A handler that returns an error
// leaves the record UNMARKED (logged + counted via HandlerErrors), so the next
// poll/rebalance redelivers it instead of skipping it (CODE-007: the handler's
// error return is no longer silently discarded — it gates the commit).
func (k *Kafka) Subscribe(ctx context.Context, topic, group string, handler Handler) error {
	resetOffset := kgo.NewOffset().AtStart()
	if k.consumeFromEnd {
		resetOffset = kgo.NewOffset().AtEnd()
	}
	opts := append([]kgo.Opt{
		kgo.SeedBrokers(k.brokers...),
		kgo.ConsumerGroup(group),
		kgo.ConsumeTopics(topic),
		// Commit only what the handler has MARKED (commit-after-process), never
		// on a blind timer. The periodic flusher still runs, but it can only
		// flush marked offsets — so it can never outrun the handler.
		kgo.AutoCommitMarks(),
		// A brand-new group reads from the start so no buffered results are lost;
		// an established group resumes from its committed offset.
		kgo.ConsumeResetOffset(resetOffset),
	}, k.extra...)
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return fmt.Errorf("bus: kafka consumer: %w", err)
	}
	defer cl.Close()

	// process runs the handler and, on success, marks the record for commit.
	// On error it counts + logs and leaves the offset uncommitted (redelivery).
	process := func(r *kgo.Record) {
		if herr := handler(ctx, Message{Topic: r.Topic, Key: r.Key, Value: r.Value}); herr != nil {
			k.handlerErr.Add(1)
			// No mark: the offset stays uncommitted so this record is redelivered.
			// Handlers that have already accounted for a message (DLQ etc.) return
			// nil; a non-nil error here means "not safely handled — keep it".
			return
		}
		cl.MarkCommitRecords(r)
	}

	for ctx.Err() == nil {
		fetches := cl.PollFetches(ctx)
		if fetches.IsClientClosed() {
			return nil
		}
		// DPR-141: the fetch response already carries each partition's high
		// watermark, so the consumer's own lag costs nothing to observe. An
		// EMPTY fetch carries it too, which is what keeps the number fresh on
		// an idle topic instead of freezing at the last busy moment.
		k.recordLag(fetches)
		if k.workers <= 1 {
			fetches.EachRecord(process)
			continue
		}
		// SCALE-001: shard the poll batch by key across bounded workers; wait
		// for the batch so offsets never run ahead of processing. Records are
		// marked per-record inside process; MarkCommitRecords is concurrency-safe.
		shards := make([][]*kgo.Record, k.workers)
		fetches.EachRecord(func(r *kgo.Record) {
			i := int(shardKey(r.Key)) % k.workers
			shards[i] = append(shards[i], r)
		})
		var wg sync.WaitGroup
		for _, shard := range shards {
			if len(shard) == 0 {
				continue
			}
			wg.Add(1)
			go func(rs []*kgo.Record) {
				defer wg.Done()
				for _, r := range rs {
					process(r)
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

// recordLag stores the largest per-partition lag in this fetch. Lag is the
// distance from the last record handed to the handler to the partition's high
// watermark; a partition whose fetch returned nothing is caught up by
// definition, so it contributes zero rather than being skipped.
func (k *Kafka) recordLag(fetches kgo.Fetches) {
	var maxLag int64
	var assignments int
	fetches.EachPartition(func(p kgo.FetchTopicPartition) {
		assignments++
		next := p.HighWatermark // no records: nothing outstanding
		if n := len(p.Records); n > 0 {
			next = p.Records[n-1].Offset + 1
		}
		if lag := p.HighWatermark - next; lag > maxLag {
			maxLag = lag
		}
	})
	if assignments == 0 {
		return // a fetch with no partitions says nothing about lag
	}
	k.lagMax.Store(maxLag)
	k.lagAssignments.Store(int64(assignments))
	k.lagSeen.Store(true)
}

// ConsumerLag implements LagReporter from the consumer's own fetch responses.
func (k *Kafka) ConsumerLag() (int64, int, bool) {
	if !k.lagSeen.Load() {
		return 0, 0, false // nothing consumed yet: no honest number to report
	}
	return k.lagMax.Load(), int(k.lagAssignments.Load()), true
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
