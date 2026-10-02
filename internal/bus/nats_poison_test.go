// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bus

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// fakeJSMsg is an in-memory jetstream.Msg that records the ack decision the
// consumer makes, so the real NATS.handleMessage can be driven without a broker.
// numDelivered is what the server stamps on each (re)delivery.
type fakeJSMsg struct {
	subject      string
	data         []byte
	hdr          nats.Header
	numDelivered uint64

	acks  int
	naks  int
	terms int
}

func (f *fakeJSMsg) Metadata() (*jetstream.MsgMetadata, error) {
	return &jetstream.MsgMetadata{NumDelivered: f.numDelivered}, nil
}
func (f *fakeJSMsg) Data() []byte                     { return f.data }
func (f *fakeJSMsg) Headers() nats.Header             { return f.hdr }
func (f *fakeJSMsg) Subject() string                  { return f.subject }
func (f *fakeJSMsg) Reply() string                    { return "" }
func (f *fakeJSMsg) Ack() error                       { f.acks++; return nil }
func (f *fakeJSMsg) DoubleAck(context.Context) error  { f.acks++; return nil }
func (f *fakeJSMsg) Nak() error                       { f.naks++; return nil }
func (f *fakeJSMsg) NakWithDelay(time.Duration) error { f.naks++; return nil }
func (f *fakeJSMsg) InProgress() error                { return nil }
func (f *fakeJSMsg) Term() error                      { f.terms++; return nil }
func (f *fakeJSMsg) TermWithReason(string) error      { f.terms++; return nil }

// drive replays the server's redelivery loop against the real handleMessage: it
// keeps redelivering (with an incrementing delivery count) until the consumer
// either acks or terminates the record, or until a safety cap is reached. The
// cap stands in for "forever" — a consumer that never stops on its own hits it.
func drive(t *testing.T, n *NATS, msg *fakeJSMsg, handler Handler) (deliveries int) {
	t.Helper()
	const serverSafetyCap = 1000
	for attempt := 1; attempt <= serverSafetyCap; attempt++ {
		msg.numDelivered = uint64(attempt)
		n.handleMessage(context.Background(), msg, handler)
		deliveries = attempt
		if msg.acks > 0 || msg.terms > 0 {
			return deliveries
		}
	}
	return deliveries
}

// TestNATSPoisonMessageStopsAfterMaxDeliver is the ING-12 regression on the NATS
// transport, driven through the REAL NATS.handleMessage with a fake message (no
// broker). A permanently-failing record must be TERMINATED after MaxDeliver
// attempts — the server told to stop — and counted as lost, never Nak'd forever.
func TestNATSPoisonMessageStopsAfterMaxDeliver(t *testing.T) {
	n := &NATS{maxDeliver: defaultNATSMaxDeliver}
	msg := &fakeJSMsg{subject: NetworkResultsTopic, data: []byte("poison"), hdr: nats.Header{}}
	msg.hdr.Set(natsKeyHeader, "tenant-x")
	poison := func(context.Context, Message) error { return errors.New("permanently unprocessable") }

	deliveries := drive(t, n, msg, poison)

	if msg.acks != 0 {
		t.Fatalf("a failing handler must never ack (acks=%d)", msg.acks)
	}
	if msg.terms == 0 {
		t.Fatalf("poison record was redelivered %d times and never terminated — unbounded redelivery (ING-12)", deliveries)
	}
	if deliveries != defaultNATSMaxDeliver {
		t.Fatalf("terminated after %d deliveries, want MaxDeliver=%d", deliveries, defaultNATSMaxDeliver)
	}
	if msg.naks != defaultNATSMaxDeliver-1 {
		t.Fatalf("naks=%d, want %d (redeliver up to the bound, then terminate)", msg.naks, defaultNATSMaxDeliver-1)
	}
	if n.HandlerLost() != 1 {
		t.Fatalf("HandlerLost=%d, want 1 — a terminated poison record is a counted loss, never silent", n.HandlerLost())
	}
	if n.handlerErr.Load() != uint64(defaultNATSMaxDeliver) {
		t.Fatalf("HandlerErrors=%d, want %d", n.handlerErr.Load(), defaultNATSMaxDeliver)
	}
}

// TestNATSUnboundedRedeliveryIsThePoisonLoop demonstrates the pre-ING-12
// behavior directly: with no delivery bound (maxDeliver<=0, which is what an
// unset MaxDeliver plus an unconditional Nak gave), the same poison record is
// Nak'd on every delivery and NEVER terminated — it loops until the test's
// safety cap, i.e. forever in production.
func TestNATSUnboundedRedeliveryIsThePoisonLoop(t *testing.T) {
	n := &NATS{maxDeliver: 0} // unbounded: the old behavior
	msg := &fakeJSMsg{subject: NetworkResultsTopic, data: []byte("poison"), hdr: nats.Header{}}
	poison := func(context.Context, Message) error { return errors.New("permanently unprocessable") }

	deliveries := drive(t, n, msg, poison)

	if msg.terms != 0 {
		t.Fatalf("an unbounded consumer must never terminate (that is the bug), terms=%d", msg.terms)
	}
	if deliveries != 1000 {
		t.Fatalf("an unbounded consumer must keep redelivering to the safety cap, stopped at %d", deliveries)
	}
	if n.HandlerLost() != 0 {
		t.Fatalf("the old behavior never counts a loss because it never gives up, HandlerLost=%d", n.HandlerLost())
	}
}

// TestNATSTransientErrorRetriesThenAcksWithinBound confirms the bound does not
// break at-least-once for transient failures: a record that fails twice then
// succeeds is redelivered and finally acked, never terminated.
func TestNATSTransientErrorRetriesThenAcksWithinBound(t *testing.T) {
	n := &NATS{maxDeliver: defaultNATSMaxDeliver}
	msg := &fakeJSMsg{subject: NetworkResultsTopic, data: []byte("v"), hdr: nats.Header{}}
	calls := 0
	handler := func(context.Context, Message) error {
		calls++
		if calls < 3 { // fail the first two deliveries, then succeed
			return errors.New("transient")
		}
		return nil
	}

	deliveries := drive(t, n, msg, handler)

	if msg.acks != 1 {
		t.Fatalf("a transient error must be redelivered until it succeeds, then acked exactly once; acks=%d", msg.acks)
	}
	if msg.terms != 0 {
		t.Fatalf("a record that eventually succeeds must never be terminated; terms=%d", msg.terms)
	}
	if deliveries != 3 || calls != 3 {
		t.Fatalf("want 3 deliveries ending in success (2 transient failures + 1 ok); deliveries=%d calls=%d", deliveries, calls)
	}
	if msg.naks != 2 {
		t.Fatalf("naks=%d, want 2 (one per transient failure)", msg.naks)
	}
	if n.HandlerLost() != 0 {
		t.Fatalf("HandlerLost=%d, want 0 (it succeeded within the bound)", n.HandlerLost())
	}
}
