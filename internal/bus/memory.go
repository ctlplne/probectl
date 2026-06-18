// SPDX-License-Identifier: LicenseRef-probectl-TBD

package bus

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	errClosed = errors.New("bus: closed")

	// ErrMemoryDropped is returned when the explicit in-memory drop policy
	// sheds a record because a subscriber buffer is full. Returning an error is
	// the important RESIL-002 contract: upstream senders must NOT ack/delete
	// their local copy after a known in-process drop.
	ErrMemoryDropped = errors.New("bus: memory subscriber buffer full - record dropped")
)

// DefaultMemoryBuffer is the per-subscriber channel depth when unset.
const DefaultMemoryBuffer = 1024

// Memory is an in-process Bus for the lightweight (<5 agent) mode and tests. It
// is a live pub/sub: a subscriber receives messages published after it
// subscribes, which matches the pipeline (the consumer starts at boot, before
// agents connect). Messages are not persisted.
type Memory struct {
	mu          sync.Mutex
	subs        map[string][]chan Message
	closed      bool
	bufSize     int
	dropOn      bool          // overflow policy: true = drop+count, false = block (U-079)
	dropped     atomic.Uint64 // messages dropped under the drop policy
	handlerErr  atomic.Uint64 // handler errors observed (CORRECT-007 — never silent)
	handlerLost atomic.Uint64 // records dropped after redelivery attempts exhausted

	flushMu   sync.Mutex
	inFlight  int
	flushWait chan struct{}
}

// memoryMaxRedeliver bounds how many times the in-memory bus re-delivers a
// record whose handler returned an error before giving up (CORRECT-007). A
// small bound matches the lightweight-mode contract: a transient handler error
// gets a few retries, but a permanently-failing handler cannot wedge the
// subscriber loop forever. Kafka redelivers via the uncommitted offset; this is
// the in-process analog. After the bound the record is counted as lost
// (HandlerLost) — never silently swallowed.
const memoryMaxRedeliver = 3

// MemoryOption configures the in-memory bus (U-079).
type MemoryOption func(*Memory)

// WithBuffer sets the per-subscriber channel depth (<=0 keeps the default).
func WithBuffer(n int) MemoryOption {
	return func(m *Memory) {
		if n > 0 {
			m.bufSize = n
		}
	}
}

// WithOverflowDrop selects the drop+count overflow policy: when a subscriber's
// buffer is full, the message is dropped, counted, and Publish returns
// ErrMemoryDropped rather than pretending the write succeeded. That keeps
// agent-side at-least-once buffers intact: the sender retries instead of
// deleting a frame that never reached storage.
func WithOverflowDrop() MemoryOption {
	return func(m *Memory) { m.dropOn = true }
}

// NewMemory returns an in-memory bus with the given options (defaults: 1024
// buffer, block-on-full, Flush waits for delivered handlers).
func NewMemory(opts ...MemoryOption) *Memory {
	m := &Memory{
		subs:      make(map[string][]chan Message),
		bufSize:   DefaultMemoryBuffer,
		flushWait: closedFlushWait(),
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Dropped returns the number of messages dropped under the drop overflow
// policy (always 0 under the default block policy).
func (m *Memory) Dropped() uint64 { return m.dropped.Load() }

// HandlerErrors returns how many times a subscriber handler returned an error
// (CORRECT-007). Each error triggers a bounded redelivery; this counts the
// errors, so they are observable rather than silently swallowed — parity with
// the Kafka bus's HandlerErrors counter.
func (m *Memory) HandlerErrors() uint64 { return m.handlerErr.Load() }

// HandlerLost returns how many records were dropped after their redelivery
// budget was exhausted (a permanently-failing handler). It is a real loss and
// is counted — never silent.
func (m *Memory) HandlerLost() uint64 { return m.handlerLost.Load() }

// subscriberCount returns the live subscriber count for a topic under the
// lock — the race-free way for tests (and callers) to await registration.
// Reading m.subs directly races the Subscribe writer (caught by -race).
func (m *Memory) subscriberCount(topic string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.subs[topic])
}

// WaitForSubscribers blocks until at least n subscribers are registered on
// topic, or ctx is done (TEST-002). It is the race-free replacement for the
// fixed pre-publish time.Sleep that tests used to "let the consumer
// subscribe": a live pub/sub bus only delivers to subscribers present at
// publish time, so a test must SYNCHRONIZE on registration, not guess a
// duration. Returns true once the count is reached, false if ctx ended first.
func (m *Memory) WaitForSubscribers(ctx context.Context, topic string, n int) bool {
	for {
		if m.subscriberCount(topic) >= n {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Millisecond):
		}
	}
}

// Publish delivers value to every current subscriber of topic. In block mode it
// back-pressures until each subscriber accepts the message. In explicit drop
// mode it still returns ErrMemoryDropped if any subscriber buffer was full, so
// upstream durability barriers can fail closed instead of ACKing lost telemetry.
func (m *Memory) Publish(ctx context.Context, topic string, key, value []byte) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errClosed
	}
	chans := append([]chan Message(nil), m.subs[topic]...)
	m.mu.Unlock()

	msg := Message{Topic: topic, Key: key, Value: value}
	var dropped bool
	for _, ch := range chans {
		if m.dropOn {
			// Drop policy: never block the publisher — a slow/stuck subscriber
			// cannot deadlock the bus in a burst (U-079); the drop is counted
			// AND returned as an error (RESIL-002) so upstream does not ACK it.
			m.addInFlight()
			select {
			case ch <- msg:
			default:
				m.doneInFlight()
				m.dropped.Add(1)
				dropped = true
			}
			continue
		}
		m.addInFlight()
		select {
		case ch <- msg:
		case <-ctx.Done():
			m.doneInFlight()
			return ctx.Err()
		}
	}
	if dropped {
		return ErrMemoryDropped
	}
	return nil
}

// Subscribe delivers topic messages to handler until ctx is canceled.
func (m *Memory) Subscribe(ctx context.Context, topic, _ string, handler Handler) error {
	ch := make(chan Message, m.bufSize)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errClosed
	}
	m.subs[topic] = append(m.subs[topic], ch)
	m.mu.Unlock()
	defer func() {
		m.removeSub(topic, ch)
		for {
			select {
			case <-ch:
				m.doneInFlight()
			default:
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case msg := <-ch:
			// CORRECT-007: a handler error is no longer silently discarded — it is
			// counted and the record is REDELIVERED up to memoryMaxRedeliver times
			// (the in-process analog of Kafka's uncommitted-offset redelivery),
			// then counted as lost if the handler keeps failing. The handler that
			// has already accounted for a message (its own DLQ etc.) returns nil.
			m.deliver(ctx, handler, msg)
			m.doneInFlight()
		}
	}
}

// deliver runs handler on msg, redelivering on error up to memoryMaxRedeliver
// times before counting the record lost (CORRECT-007). A canceled context stops
// retrying promptly so shutdown never hangs.
func (m *Memory) deliver(ctx context.Context, handler Handler, msg Message) {
	for attempt := 0; ; attempt++ {
		if err := handler(ctx, msg); err == nil {
			return
		}
		m.handlerErr.Add(1)
		if attempt >= memoryMaxRedeliver || ctx.Err() != nil {
			m.handlerLost.Add(1)
			return
		}
	}
}

// Flush waits until every message accepted by Publish has finished its
// subscriber handler path. That turns the in-process bus into a real ACK
// barrier for the agent stream: memory mode is still not a broker, but a result
// is not acknowledged while it is merely sitting in a volatile Go channel.
func (m *Memory) Flush(ctx context.Context) error {
	for {
		m.flushMu.Lock()
		if m.inFlight == 0 {
			m.flushMu.Unlock()
			return nil
		}
		wait := m.flushWait
		m.flushMu.Unlock()

		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (m *Memory) addInFlight() {
	m.flushMu.Lock()
	defer m.flushMu.Unlock()
	if m.inFlight == 0 {
		m.flushWait = make(chan struct{})
	}
	m.inFlight++
}

func (m *Memory) doneInFlight() {
	m.flushMu.Lock()
	defer m.flushMu.Unlock()
	if m.inFlight == 0 {
		return
	}
	m.inFlight--
	if m.inFlight == 0 {
		close(m.flushWait)
	}
}

func closedFlushWait() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// Close marks the bus closed.
func (m *Memory) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *Memory) removeSub(topic string, ch chan Message) {
	m.mu.Lock()
	defer m.mu.Unlock()
	subs := m.subs[topic]
	for i, c := range subs {
		if c == ch {
			m.subs[topic] = append(subs[:i], subs[i+1:]...)
			break
		}
	}
}
