package bus

import (
	"context"
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

// TestKafkaPublishSubscribe exercises the real Kafka client path against an
// in-process kfake broker (Kafka protocol, no JVM/Docker needed).
func TestKafkaPublishSubscribe(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.SeedTopics(1, NetworkResultsTopic))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()

	b, err := NewKafka(cluster.ListenAddrs())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	testPubSub(t, b)
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
