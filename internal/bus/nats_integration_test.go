// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bus

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
)

// natsServers is the test server, e.g. PROBECTL_TEST_NATS=nats://127.0.0.1:4222
// (a JetStream-enabled server; the compose dev stack ships one).
func natsServers(t *testing.T) []string {
	t.Helper()
	v := os.Getenv("PROBECTL_TEST_NATS")
	if v == "" {
		// A required suite that quietly skips is vacuous green: in CI, where
		// PROBECTL_TEST_REQUIRE_SERVICES is set, a missing server fails.
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_NATS not set (a JetStream-enabled NATS server, e.g. the dev compose stack's nats service)")
	}
	return []string{v}
}

func testNATS(t *testing.T) *NATS {
	t.Helper()
	// The dev server is plaintext on loopback; production refuses that (the
	// policy is proved in the unit tests).
	b, err := NewNATS(natsServers(t), StreamPolicy{MaxAge: time.Hour}, 512)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return b
}

// TestNATSDeliversAtLeastOnceAndAcksOnlyAfterTheHandler (DPR-119): the durable
// lightweight transport carries the same delivery contract as Kafka. A handler
// that fails must NOT advance the consumer's position, or "at-least-once" is a
// claim rather than a property.
func TestNATSDeliversAtLeastOnceAndAcksOnlyAfterTheHandler(t *testing.T) {
	b := testNATS(t)
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	topic := fmt.Sprintf("probectl.test-%d.network.results", time.Now().UnixNano())
	group := fmt.Sprintf("itest-%d", time.Now().UnixNano())

	var mu sync.Mutex
	var seen []string
	failFirst := map[string]bool{"b": true}
	done := make(chan struct{})
	go func() {
		_ = b.Subscribe(ctx, topic, group, func(_ context.Context, m Message) error {
			mu.Lock()
			seen = append(seen, string(m.Value))
			first := failFirst[string(m.Value)]
			if first {
				failFirst[string(m.Value)] = false
			}
			n := len(seen)
			mu.Unlock()
			if first {
				return fmt.Errorf("handler refuses %s once", m.Value)
			}
			if n >= 4 {
				close(done)
			}
			return nil
		})
	}()

	for _, v := range []string{"a", "b", "c"} {
		if err := b.Publish(ctx, topic, []byte("tenant-x"), []byte(v)); err != nil {
			t.Fatalf("publish %s: %v", v, err)
		}
	}
	if err := b.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	select {
	case <-done:
	case <-time.After(45 * time.Second):
		t.Fatalf("timed out; seen=%v", seen)
	}
	mu.Lock()
	defer mu.Unlock()
	count := map[string]int{}
	for _, v := range seen {
		count[v]++
	}
	if count["b"] < 2 {
		t.Errorf("a failed handler must leave the record for redelivery: %v", seen)
	}
	if count["a"] == 0 || count["c"] == 0 {
		t.Errorf("every record must arrive: %v", seen)
	}
	if b.Stats().HandlerErrors == 0 {
		t.Error("a handler error must be counted")
	}
}

// TestNATSKeyAndTenantAttributionSurviveTheWire (DPR-119): NATS has no
// partition key, and internal/pipeline authenticates the tenant from the record
// KEY. If the key did not survive, every record would fail tenant verification
// and the plane would go quiet with no obvious cause.
func TestNATSKeyAndTenantAttributionSurviveTheWire(t *testing.T) {
	b := testNATS(t)
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	topic := fmt.Sprintf("probectl.test-%d.ebpf.flows", time.Now().UnixNano())
	group := fmt.Sprintf("itest-key-%d", time.Now().UnixNano())
	key := TenantKey("88929fbe-28e5-4f0a-898e-6c4302c55e57", "agent-7")

	got := make(chan Message, 1)
	go func() {
		_ = b.Subscribe(ctx, topic, group, func(_ context.Context, m Message) error {
			select {
			case got <- m:
			default:
			}
			return nil
		})
	}()
	if err := b.Publish(ctx, topic, key, []byte("payload")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := b.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	select {
	case m := <-got:
		if string(m.Key) != string(key) {
			t.Fatalf("key = %q, want %q", m.Key, key)
		}
		if TenantFromKey(m.Key) != "88929fbe-28e5-4f0a-898e-6c4302c55e57" {
			t.Fatalf("tenant attribution lost: %q", TenantFromKey(m.Key))
		}
		if m.Topic != topic {
			t.Fatalf("topic = %q", m.Topic)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("no message")
	}
}

// TestNATSConsumerPositionSurvivesAReconnect (DPR-119): a durable consumer's
// position lives on the server, so a process that stops and comes back does not
// replay what it already acknowledged. This is the property the volatile
// lightweight mode does not have, and the reason this mode exists.
func TestNATSConsumerPositionSurvivesAReconnect(t *testing.T) {
	servers := natsServers(t)
	topic := fmt.Sprintf("probectl.test-%d.flow.events", time.Now().UnixNano())
	group := fmt.Sprintf("itest-resume-%d", time.Now().UnixNano())

	first, err := NewNATS(servers, StreamPolicy{MaxAge: time.Hour}, 512)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for i := 0; i < 5; i++ {
		if err := first.Publish(ctx, topic, []byte("t"), []byte(fmt.Sprintf("m%d", i))); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}
	if err := first.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}

	consume := func(b *NATS, want int) []string {
		cctx, ccancel := context.WithTimeout(ctx, 30*time.Second)
		defer ccancel()
		var mu sync.Mutex
		var got []string
		done := make(chan struct{})
		go func() {
			_ = b.Subscribe(cctx, topic, group, func(_ context.Context, m Message) error {
				mu.Lock()
				got = append(got, string(m.Value))
				n := len(got)
				mu.Unlock()
				if n == want {
					close(done)
				}
				return nil
			})
		}()
		select {
		case <-done:
		case <-cctx.Done():
		}
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}

	if got := consume(first, 5); len(got) != 5 {
		t.Fatalf("first pass got %v", got)
	}
	_ = first.Close()

	// A new process, the same durable name: nothing already acknowledged comes
	// back, and a record published while it was away does.
	second, err := NewNATS(servers, StreamPolicy{MaxAge: time.Hour}, 512)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	defer second.Close()
	if err := second.Publish(ctx, topic, []byte("t"), []byte("after-restart")); err != nil {
		t.Fatalf("publish after restart: %v", err)
	}
	if err := second.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	got := consume(second, 1)
	if len(got) != 1 || got[0] != "after-restart" {
		t.Fatalf("a durable consumer must resume, not replay: got %v", got)
	}
}

// TestNATSStreamsAreCreatedPerTopicAndListable (DPR-119): the preflight that
// names missing topics works the same way, and a per-tenant lane is a stream of
// its own.
func TestNATSStreamsAreCreatedPerTopicAndListable(t *testing.T) {
	b := testNATS(t)
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stamp := time.Now().UnixNano()
	a := fmt.Sprintf("probectl.t-acme-%d.ebpf.flows", stamp)
	g := fmt.Sprintf("probectl.t-globex-%d.ebpf.flows", stamp)

	missing, err := b.TopicsMissing(ctx, []string{a, g})
	if err != nil {
		t.Fatalf("topics missing: %v", err)
	}
	if len(missing) != 2 {
		t.Fatalf("both lanes must be reported missing first: %v", missing)
	}
	created, err := b.EnsureTopics(ctx, []string{a, g}, 1, 1)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if len(created) != 2 {
		t.Fatalf("created = %v", created)
	}
	missing, err = b.TopicsMissing(ctx, []string{a, g})
	if err != nil || len(missing) != 0 {
		t.Fatalf("after ensure: missing=%v err=%v", missing, err)
	}
}
