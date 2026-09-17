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

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// NATS is the DURABLE LIGHTWEIGHT bus: NATS with JetStream (DPR-119).
//
// The product advertised a "lightweight mode" for small deployments beside the
// Kafka default, and shipped only an in-process memory bus that loses every
// record when the process exits. So a deployment that wanted anything smaller
// than Kafka had no supported option at all — the chart's own README says
// volatile modes are unsupported for durable use, and it was right.
//
// The two are now named separately and never conflated:
//
//	volatile lightweight  — mode "memory": single process, nothing survives a
//	                        restart. Development and tests ONLY.
//	durable lightweight   — mode "nats": one small broker, records on disk,
//	                        durable consumers whose position survives a restart
//	                        and a rolling upgrade. Production-supportable.
//
// Everything the Kafka transport promises, this promises, because the same
// pipeline runs on top of it:
//
//   - a topic is a subject and a stream of its own, so per-tenant lanes stay
//     separate and a siloed tenant's records never share a lane with anyone;
//   - the record KEY (the authenticated tenant attribution that
//     internal/pipeline verifies) travels in a header, because NATS has no
//     partition key — a record without it is still delivered and still fails
//     tenant verification, exactly as an unkeyed Kafka record does;
//   - delivery is at-least-once and VERIFIED, never assumed (the DPR-071
//     contract): Publish is asynchronous and bounded, every publish is
//     acknowledged by the server, failures are counted and reportable, and
//     Flush is the durability barrier;
//   - a consumer group is a durable consumer, its position lives on the server,
//     and a message is acknowledged only after the handler returns nil;
//   - abandoned per-replica view consumers are sweepable (DPR-109), and the
//     server also expires them on its own after an inactivity threshold.
type NATS struct {
	conn   *nats.Conn
	js     jetstream.JetStream
	stream StreamPolicy

	workers    int
	maxPending int

	produced    atomic.Uint64
	failed      atomic.Uint64
	shed        atomic.Uint64
	handlerErr  atomic.Uint64
	inflight    atomic.Int64
	lastFailure atomic.Pointer[produceFailure]

	mu      sync.Mutex
	streams map[string]struct{} // topics whose stream this process has ensured
}

// StreamPolicy is the durability policy applied to every stream this bus
// creates. Zero values take the defaults below.
type StreamPolicy struct {
	// MaxAge is how long a record stays on the broker (Kafka's retention.ms).
	MaxAge time.Duration
	// Replicas is the JetStream replica count (1 on a single broker — the
	// point of the lightweight mode; 3 on a small cluster).
	Replicas int
	// InactiveThreshold expires a durable consumer nobody has used for this
	// long. It is the server-side half of the DPR-109 sweep.
	InactiveThreshold time.Duration
}

const (
	defaultNATSMaxAge            = 7 * 24 * time.Hour
	defaultNATSInactiveThreshold = 7 * 24 * time.Hour
	defaultNATSMaxPending        = 4096
	// natsKeyHeader carries the Kafka-style record key. Tenant attribution
	// rides on it, so it is not optional metadata: the pipeline reads it.
	natsKeyHeader = "Probectl-Key"
)

// NewNATS connects to the given servers and prepares JetStream.
func NewNATS(servers []string, policy StreamPolicy, maxPending int, opts ...nats.Option) (*NATS, error) {
	if len(servers) == 0 {
		return nil, errors.New("bus: nats mode requires at least one server URL")
	}
	if policy.MaxAge <= 0 {
		policy.MaxAge = defaultNATSMaxAge
	}
	if policy.Replicas <= 0 {
		policy.Replicas = 1
	}
	if policy.InactiveThreshold <= 0 {
		policy.InactiveThreshold = defaultNATSInactiveThreshold
	}
	if maxPending <= 0 {
		maxPending = defaultNATSMaxPending
	}
	opts = append([]nats.Option{
		nats.Name("probectl"),
		nats.MaxReconnects(-1),
		nats.RetryOnFailedConnect(true),
		nats.ReconnectWait(time.Second),
	}, opts...)
	conn, err := nats.Connect(strings.Join(servers, ","), opts...)
	if err != nil {
		return nil, fmt.Errorf("bus: nats connect: %w", err)
	}
	js, err := jetstream.New(conn, jetstream.WithPublishAsyncMaxPending(maxPending))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("bus: jetstream: %w", err)
	}
	return &NATS{
		conn:       conn,
		js:         js,
		stream:     policy,
		workers:    1,
		maxPending: maxPending,
		streams:    map[string]struct{}{},
	}, nil
}

// WithSubscribeWorkers shards each delivered batch across n workers by key,
// mirroring the Kafka bus (SCALE-001).
func (n *NATS) WithSubscribeWorkers(w int) *NATS {
	if w > 0 {
		n.workers = w
	}
	return n
}

// streamName maps a topic to a JetStream stream name. Stream names cannot
// contain dots, so the topic's segments are joined with underscores; the topic
// itself remains the subject, one stream per topic exactly as Kafka has one
// topic per topic.
func streamName(topic string) string {
	return strings.NewReplacer(".", "_", "*", "_", ">", "_", " ", "_").Replace(topic)
}

// durableName maps a consumer group to a JetStream durable name, which has the
// same character restrictions as a stream name.
func durableName(group string) string {
	return streamName(group)
}

// ensureStream creates the stream for a topic if this process has not already
// done so. Creating is idempotent, so a racing replica is not an error.
func (n *NATS) ensureStream(ctx context.Context, topic string) error {
	n.mu.Lock()
	_, done := n.streams[topic]
	n.mu.Unlock()
	if done {
		return nil
	}
	if _, err := n.js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:     streamName(topic),
		Subjects: []string{topic},
		// Records leave on age or size, never because a consumer read them:
		// several view groups read the same lane independently.
		Retention: jetstream.LimitsPolicy,
		Storage:   jetstream.FileStorage,
		MaxAge:    n.stream.MaxAge,
		Replicas:  n.stream.Replicas,
		Discard:   jetstream.DiscardOld,
	}); err != nil {
		return fmt.Errorf("bus: nats ensure stream for %s: %w", topic, err)
	}
	n.mu.Lock()
	n.streams[topic] = struct{}{}
	n.mu.Unlock()
	return nil
}

// Publish sends value to topic. It is ASYNCHRONOUS and bounded, like the Kafka
// producer: the call returns once the record is accepted, and the server's
// acknowledgement is accounted in the background (Stats / PublishFailures /
// Flush). A full in-flight window sheds rather than blocking the caller.
func (n *NATS) Publish(ctx context.Context, topic string, key, value []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := n.ensureStream(context.WithoutCancel(ctx), topic); err != nil {
		n.failed.Add(1)
		n.recordFailure(topic, err)
		return err
	}
	if n.inflight.Load() >= int64(n.maxPending) {
		n.shed.Add(1)
		return ErrPublishShed
	}
	msg := &nats.Msg{Subject: topic, Data: value, Header: nats.Header{}}
	if len(key) > 0 {
		msg.Header.Set(natsKeyHeader, string(key))
	}
	future, err := n.js.PublishMsgAsync(msg)
	if err != nil {
		if errors.Is(err, jetstream.ErrTooManyStalledMsgs) || errors.Is(err, nats.ErrMaxPayload) {
			n.shed.Add(1)
			return ErrPublishShed
		}
		n.failed.Add(1)
		n.recordFailure(topic, err)
		return fmt.Errorf("bus: nats publish: %w", err)
	}
	n.inflight.Add(1)
	go func() {
		defer n.inflight.Add(-1)
		select {
		case <-future.Ok():
			n.produced.Add(1)
		case e := <-future.Err():
			n.failed.Add(1)
			n.recordFailure(topic, e)
		}
	}()
	return nil
}

// Flush blocks until every record published so far has been acknowledged by
// the server (or ctx expires). This is the durability barrier a caller uses
// before acking an upstream producer (CORRECT-004).
func (n *NATS) Flush(ctx context.Context) error {
	select {
	case <-n.js.PublishAsyncComplete():
	case <-ctx.Done():
		return n.flushError(ctx.Err())
	}
	// PublishAsyncComplete returns when the client has no pending publishes;
	// the accounting goroutines may still be finishing, so wait for them too.
	for n.inflight.Load() > 0 {
		select {
		case <-ctx.Done():
			return n.flushError(ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	return nil
}

func (n *NATS) flushError(err error) error {
	if err == nil {
		return nil
	}
	if f := n.lastFailure.Load(); f != nil {
		return fmt.Errorf("%w (last publish failure on %s: %v)", err, f.topic, f.err)
	}
	return err
}

func (n *NATS) recordFailure(topic string, err error) {
	n.lastFailure.Store(&produceFailure{topic: topic, err: err})
}

// PublishFailures implements PublishFailureReporter (DPR-071): records that
// Publish accepted and the server never acknowledged, plus records shed at the
// bound, plus the last such error.
func (n *NATS) PublishFailures() (failed, shed uint64, last error) {
	if f := n.lastFailure.Load(); f != nil {
		last = fmt.Errorf("last publish failure on %s: %w", f.topic, f.err)
	}
	return n.failed.Load(), n.shed.Load(), last
}

// Stats reports the cumulative producer counters.
func (n *NATS) Stats() PublishStats {
	return PublishStats{
		Produced:      n.produced.Load(),
		Failed:        n.failed.Load(),
		Shed:          n.shed.Load(),
		Buffered:      n.inflight.Load(),
		HandlerErrors: n.handlerErr.Load(),
	}
}

// Subscribe consumes topic through a durable consumer named after group until
// ctx is canceled. It blocks.
//
// Delivery is at-least-once with the SAME contract as the Kafka bus: a message
// is acknowledged only after the handler returns nil. A handler error leaves
// the message unacknowledged (counted in HandlerErrors) and the server
// redelivers it — the error return gates the ack, it is never discarded.
func (n *NATS) Subscribe(ctx context.Context, topic, group string, handler Handler) error {
	if err := n.ensureStream(ctx, topic); err != nil {
		return err
	}
	cons, err := n.js.CreateOrUpdateConsumer(ctx, streamName(topic), jetstream.ConsumerConfig{
		Durable:   durableName(group),
		AckPolicy: jetstream.AckExplicitPolicy,
		// A brand-new durable reads from the start so nothing buffered is lost;
		// an established one resumes from its own acknowledged position, which
		// is what survives a restart and a rolling upgrade.
		DeliverPolicy: jetstream.DeliverAllPolicy,
		FilterSubject: topic,
		AckWait:       30 * time.Second,
		MaxAckPending: 1024,
		// DPR-109: the server retires a durable nobody has used for this long,
		// so abandoned per-replica view consumers cannot pile up even if no
		// sweep ever runs.
		InactiveThreshold: n.stream.InactiveThreshold,
	})
	if err != nil {
		return fmt.Errorf("bus: nats consumer %s on %s: %w", group, topic, err)
	}

	process := func(msg jetstream.Msg) {
		m := Message{Topic: msg.Subject(), Value: msg.Data()}
		if h := msg.Headers().Get(natsKeyHeader); h != "" {
			m.Key = []byte(h)
		}
		if herr := handler(ctx, m); herr != nil {
			n.handlerErr.Add(1)
			// No ack: the server redelivers after AckWait. The delay keeps a
			// permanently failing record from spinning the consumer.
			_ = msg.NakWithDelay(time.Second)
			return
		}
		_ = msg.Ack()
	}

	iter, err := cons.Messages(jetstream.PullMaxMessages(256))
	if err != nil {
		return fmt.Errorf("bus: nats messages on %s: %w", topic, err)
	}
	defer iter.Stop()
	go func() {
		<-ctx.Done()
		iter.Stop()
	}()

	for ctx.Err() == nil {
		msg, err := iter.Next()
		if err != nil {
			if errors.Is(err, jetstream.ErrMsgIteratorClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("bus: nats fetch on %s: %w", topic, err)
		}
		process(msg)
	}
	return nil
}

// Close flushes what is in flight (bounded, so shutdown never hangs on a dead
// broker) and closes the connection.
func (n *NATS) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = n.Flush(ctx)
	n.conn.Close()
	return nil
}

// TopicsMissing returns the subset of topics with no stream yet (DPR-047).
// It never creates anything.
func (n *NATS) TopicsMissing(ctx context.Context, topics []string) ([]string, error) {
	if len(topics) == 0 {
		return nil, nil
	}
	have := map[string]struct{}{}
	names := n.js.StreamNames(ctx)
	for name := range names.Name() {
		have[name] = struct{}{}
	}
	if err := names.Err(); err != nil {
		return nil, fmt.Errorf("bus: nats list streams: %w", err)
	}
	var missing []string
	for _, t := range topics {
		if _, ok := have[streamName(t)]; !ok {
			missing = append(missing, t)
		}
	}
	sort.Strings(missing)
	return missing, nil
}

// EnsureTopics creates a stream for every missing topic, returning the ones it
// created. partitions is accepted for interface parity and ignored: a JetStream
// stream is ordered as a whole, which is why the durable lightweight mode is
// for small deployments. replication maps to the stream's replica count.
func (n *NATS) EnsureTopics(ctx context.Context, topics []string, _ int32, replication int16) ([]string, error) {
	missing, err := n.TopicsMissing(ctx, topics)
	if err != nil {
		return nil, err
	}
	if len(missing) == 0 {
		return nil, nil
	}
	policy := n.stream
	if replication > 0 {
		policy.Replicas = int(replication)
	}
	var created []string
	for _, t := range missing {
		if _, err := n.js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
			Name:      streamName(t),
			Subjects:  []string{t},
			Retention: jetstream.LimitsPolicy,
			Storage:   jetstream.FileStorage,
			MaxAge:    policy.MaxAge,
			Replicas:  policy.Replicas,
			Discard:   jetstream.DiscardOld,
		}); err != nil {
			return created, fmt.Errorf("bus: nats refused to create stream for %s: %w", t, err)
		}
		created = append(created, t)
	}
	sort.Strings(created)
	return created, nil
}

// natsGroupIdle is how long a durable consumer must have been untouched before
// the sweep treats it as abandoned. A live consumer between fetches can show
// zero waiters for an instant; a consumer no process has fetched from in this
// long belongs to a process that is gone.
const natsGroupIdle = 5 * time.Minute

// ListEmptyGroups implements GroupJanitor (DPR-109): durable consumers that
// nobody is consuming. A consumer qualifies when no pull request is waiting on
// it, nothing is awaiting acknowledgement, and it has not delivered anything
// recently.
func (n *NATS) ListEmptyGroups(ctx context.Context) ([]string, error) {
	var empty []string
	streams := n.js.ListStreams(ctx)
	for si := range streams.Info() {
		st, err := n.js.Stream(ctx, si.Config.Name)
		if err != nil {
			return nil, fmt.Errorf("bus: nats open stream %s: %w", si.Config.Name, err)
		}
		consumers := st.ListConsumers(ctx)
		for ci := range consumers.Info() {
			if ci.NumWaiting > 0 || ci.NumAckPending > 0 || ci.PushBound {
				continue
			}
			idleSince := ci.Delivered.Last
			if idleSince == nil || ci.TimeStamp.Sub(*idleSince) > natsGroupIdle {
				empty = append(empty, ci.Name)
			}
		}
		if err := consumers.Err(); err != nil {
			return nil, fmt.Errorf("bus: nats list consumers: %w", err)
		}
	}
	if err := streams.Err(); err != nil {
		return nil, fmt.Errorf("bus: nats list streams: %w", err)
	}
	sort.Strings(empty)
	return dedupe(empty), nil
}

// DeleteGroups implements GroupJanitor: remove durable consumers and the
// position they hold. A consumer that is already gone is not an error.
func (n *NATS) DeleteGroups(ctx context.Context, groups []string) ([]string, error) {
	if len(groups) == 0 {
		return nil, nil
	}
	want := map[string]struct{}{}
	for _, g := range groups {
		want[durableName(g)] = struct{}{}
	}
	var deleted []string
	var refused error
	streams := n.js.ListStreams(ctx)
	for si := range streams.Info() {
		for name := range want {
			err := n.js.DeleteConsumer(ctx, si.Config.Name, name)
			switch {
			case err == nil:
				deleted = append(deleted, name)
			case errors.Is(err, jetstream.ErrConsumerNotFound):
			default:
				if refused == nil {
					refused = fmt.Errorf("bus: nats refused to delete consumer %s: %w", name, err)
				}
			}
		}
	}
	if err := streams.Err(); err != nil && refused == nil {
		refused = fmt.Errorf("bus: nats list streams: %w", err)
	}
	sort.Strings(deleted)
	return dedupe(deleted), refused
}

func dedupe(in []string) []string {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
