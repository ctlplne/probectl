// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bus

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"
)

func TestMemoryPublishSubscribe(t *testing.T) {
	b := NewMemory()
	defer b.Close()
	testPubSub(t, b)
}

func TestMemorySubscribeWorkersFlushAllAcceptedMessages(t *testing.T) {
	b := NewMemory(WithBuffer(256), WithSubscribeWorkers(8))
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got := make(chan byte, 256)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = b.Subscribe(ctx, NetworkResultsTopic, "workers", func(_ context.Context, m Message) error {
			if len(m.Value) > 0 {
				got <- m.Value[0]
			}
			return nil
		})
	}()
	if !b.WaitForSubscribers(ctx, NetworkResultsTopic, 1) {
		t.Fatal("subscriber did not register")
	}
	for i := 0; i < 200; i++ {
		if err := b.Publish(ctx, NetworkResultsTopic, []byte("tenant-1"), []byte{byte(i)}); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}
	if err := b.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if gotLen := len(got); gotLen != 200 {
		t.Fatalf("worker subscriber delivered %d messages after flush, want 200", gotLen)
	}
	cancel()
	wg.Wait()
}

// TestKafkaPublishSubscribe exercises the real Kafka client path against an
// in-process kfake broker (Kafka protocol, no JVM/Docker needed).
func TestKafkaPublishSubscribe(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.SeedTopics(1, NetworkResultsTopic))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()

	b, err := NewKafka(cluster.ListenAddrs(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	testPubSub(t, b)
}

func TestKafkaSubscribeFromEndSkipsExistingRecords(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.SeedTopics(1, NetworkResultsTopic))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()

	b, err := NewKafka(cluster.ListenAddrs(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, v := range []byte{0, 1} {
		if err := b.Publish(ctx, NetworkResultsTopic, []byte("tenant-1"), []byte{v}); err != nil {
			t.Fatalf("publish old %d: %v", v, err)
		}
	}
	if err := b.Flush(ctx); err != nil {
		t.Fatalf("flush old records: %v", err)
	}

	b.WithSubscribeFromEnd()
	got := make(chan byte, 16)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = b.Subscribe(ctx, NetworkResultsTopic, "from-end-test", func(_ context.Context, m Message) error {
			if len(m.Value) > 0 {
				got <- m.Value[0]
			}
			return nil
		})
	}()

	time.Sleep(500 * time.Millisecond)
	if err := b.Publish(ctx, NetworkResultsTopic, []byte("tenant-1"), []byte{9}); err != nil {
		t.Fatalf("publish new record: %v", err)
	}
	if err := b.Flush(ctx); err != nil {
		t.Fatalf("flush new record: %v", err)
	}

	select {
	case v := <-got:
		if v != 9 {
			t.Fatalf("from-end subscriber saw old record %d", v)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("from-end subscriber did not see the new record")
	}
	select {
	case v := <-got:
		t.Fatalf("from-end subscriber consumed stale record %d", v)
	case <-time.After(500 * time.Millisecond):
	}
	cancel()
	wg.Wait()
}

// testPubSub publishes three messages and asserts the subscriber receives them.
func testPubSub(t *testing.T, b Bus) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	got := make(chan byte, 16)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = b.Subscribe(ctx, NetworkResultsTopic, "test-group", func(_ context.Context, m Message) error {
			if len(m.Value) > 0 {
				got <- m.Value[0]
			}
			return nil
		})
	}()

	// Let the subscriber register / join the consumer group.
	time.Sleep(500 * time.Millisecond)
	for i := byte(0); i < 3; i++ {
		if err := b.Publish(ctx, NetworkResultsTopic, []byte("tenant-1"), []byte{i}); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}

	received := map[byte]bool{}
	timeout := time.After(25 * time.Second)
	for len(received) < 3 {
		select {
		case v := <-got:
			received[v] = true
		case <-timeout:
			t.Fatalf("received only %d/3 messages", len(received))
		}
	}
	cancel()
	wg.Wait()

	for i := byte(0); i < 3; i++ {
		if !received[i] {
			t.Errorf("missing message %d", i)
		}
	}
}

// U-010: kafka without TLS is refused unless the explicit dev flag is set;
// with the flag, the wired client still round-trips against kfake.
func TestKafkaPlaintextRefusedWithoutDevFlag(t *testing.T) {
	if _, err := New("kafka", []string{"broker:9092"}, Security{}); err == nil {
		t.Fatal("plaintext kafka must be refused without the explicit dev flag")
	}
	cluster, err := kfake.NewCluster(kfake.SeedTopics(1, NetworkResultsTopic))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	b, err := New("kafka", cluster.ListenAddrs(), Security{AllowPlaintext: true})
	if err != nil {
		t.Fatalf("explicit dev flag must connect: %v", err)
	}
	defer b.Close()
	testPubSub(t, b)
}

// The TLS/SASL option builders fail closed on bad input and produce options
// on good input.
func TestBusSecurityPolicy(t *testing.T) {
	if err := (Security{SASLMechanism: "scram-sha-1"}).Validate(); err == nil {
		t.Fatal("unknown SASL mechanism must fail validation")
	}
	if err := (Security{TLSEnabled: true, SASLMechanism: "plain"}).Validate(); err == nil {
		t.Fatal("SASL without credentials must fail validation")
	}
	if err := (Security{TLSEnabled: true, CertFile: "only-cert.pem"}).Validate(); err == nil {
		t.Fatal("client cert without key must fail validation")
	}
	sec := Security{TLSEnabled: true, SASLMechanism: "scram-sha-512", SASLUser: "u", SASLPassword: "p"}
	if err := sec.Validate(); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	opts, err := sec.kgoOpts()
	if err != nil {
		t.Fatalf("kgoOpts: %v", err)
	}
	if len(opts) != 2 { // DialTLSConfig + SASL
		t.Fatalf("opts = %d, want 2 (TLS + SASL)", len(opts))
	}
	if _, err := (Security{TLSEnabled: true, CAFile: "/does/not/exist.pem"}).kgoOpts(); err == nil {
		t.Fatal("missing CA file must fail")
	}
}

// DPR-141: the lag seam must be exercised for every transport a deployment can
// select, and a transport that cannot report lag must say so rather than
// returning a zero that reads as a caught-up consumer.
func TestEveryTransportEitherReportsLagOrSaysItCannot(t *testing.T) {
	// The in-process bus reports it; an unsubscribed one reports unavailable.
	mem := NewMemory()
	defer func() { _ = mem.Close() }()
	var _ LagReporter = mem
	if lag, n, ok := mem.ConsumerLag(); ok || lag != 0 || n != 0 {
		t.Errorf("an idle in-process bus must report unavailable, got %d/%d/%v", lag, n, ok)
	}

	// Kafka and NATS implement the seam; before anything is consumed they must
	// report unavailable rather than a confident zero.
	k := &Kafka{}
	var _ LagReporter = k
	if lag, n, ok := k.ConsumerLag(); ok || lag != 0 || n != 0 {
		t.Errorf("kafka before any fetch must report unavailable, got %d/%d/%v", lag, n, ok)
	}
	nb := &NATS{}
	var _ LagReporter = nb
	if lag, n, ok := nb.ConsumerLag(); ok || lag != 0 || n != 0 {
		t.Errorf("nats before any delivery must report unavailable, got %d/%d/%v", lag, n, ok)
	}
}

// The control plane must publish the lag series for any transport, and must
// publish the unavailable marker even when the transport lacks the capability —
// an absent series is indistinguishable from a healthy one on a dashboard.
func TestControlPlanePublishesLagSeriesForEveryTransport(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "probectl-control", "builders.go"))
	if err != nil {
		t.Fatalf("read builders.go: %v", err)
	}
	s := string(src)
	for _, want := range []string{
		"probectl_bus_consumer_lag_max",
		"probectl_bus_consumer_lag_assignments",
		"probectl_bus_consumer_lag_unavailable",
		"bus.LagReporter",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("control plane does not publish %q (DPR-141)", want)
		}
	}
	// The else branch is the point: no capability still publishes the marker.
	if strings.Count(s, "probectl_bus_consumer_lag_unavailable") < 2 {
		t.Error("the unavailable marker must also be published when the transport lacks the capability")
	}
}
