package bus

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

var errClosed = errors.New("bus: closed")

// DefaultMemoryBuffer is the per-subscriber channel depth when unset.
const DefaultMemoryBuffer = 1024

// Memory is an in-process Bus for the lightweight (<5 agent) mode and tests. It
// is a live pub/sub: a subscriber receives messages published after it
// subscribes, which matches the pipeline (the consumer starts at boot, before
// agents connect). Messages are not persisted.
type Memory struct {
	mu      sync.Mutex
	subs    map[string][]chan Message
	closed  bool
	bufSize int
	dropOn  bool          // overflow policy: true = drop+count, false = block (U-079)
	dropped atomic.Uint64 // messages dropped under the drop policy
}

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
// buffer is full, the message is dropped and counted rather than blocking the
// publisher (the default is block). Drops are surfaced via Dropped() — never
// silent (an observability tool that loses data hides a correctness gap).
func WithOverflowDrop() MemoryOption {
	return func(m *Memory) { m.dropOn = true }
}

// NewMemory returns an in-memory bus with the given options (defaults: 1024
// buffer, block-on-full).
func NewMemory(opts ...MemoryOption) *Memory {
	m := &Memory{subs: make(map[string][]chan Message), bufSize: DefaultMemoryBuffer}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Dropped returns the number of messages dropped under the drop overflow
// policy (always 0 under the default block policy).
func (m *Memory) Dropped() uint64 { return m.dropped.Load() }

// Publish delivers value to every current subscriber of topic.
func (m *Memory) Publish(ctx context.Context, topic string, key, value []byte) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errClosed
	}
	chans := append([]chan Message(nil), m.subs[topic]...)
	m.mu.Unlock()

	msg := Message{Topic: topic, Key: key, Value: value}
	for _, ch := range chans {
		if m.dropOn {
			// Drop policy: never block the publisher — a slow/stuck subscriber
			// cannot deadlock the bus in a burst (U-079); the drop is counted.
			select {
			case ch <- msg:
			default:
				m.dropped.Add(1)
			}
			continue
		}
		select {
		case ch <- msg:
		case <-ctx.Done():
			return ctx.Err()
		}
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
	defer m.removeSub(topic, ch)

	for {
		select {
		case <-ctx.Done():
			return nil
		case msg := <-ch:
			// Handler errors are the handler's concern (it retries/logs); the
			// in-memory bus does not redeliver.
			_ = handler(ctx, msg)
		}
	}
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
