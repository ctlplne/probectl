package bus

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
)

// U-004: Publish never blocks on a degraded broker. Against an UNREACHABLE
// broker with a tiny bounded buffer, the first records are accepted
// instantly, the overflow is shed with ErrPublishShed (counted), every call
// returns fast (p99 isolated from the broker), and Close does not deadlock.
func TestAsyncPublishShedsOnUnreachableBroker(t *testing.T) {
	b, err := NewKafka([]string{"127.0.0.1:1"}, 8, // nothing listens here; tiny bound
		kgo.RetryTimeout(500*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}

	const calls = 200
	lat := make([]time.Duration, 0, calls)
	sheds := 0
	for i := 0; i < calls; i++ {
		t0 := time.Now()
		err := b.Publish(context.Background(), NetworkResultsTopic, []byte("t1"), []byte("v"))
		lat = append(lat, time.Since(t0))
		if errors.Is(err, ErrPublishShed) {
			sheds++
		} else if err != nil {
			t.Fatalf("unexpected publish error: %v", err)
		}
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p99 := lat[len(lat)*99/100-1]
	if p99 > 100*time.Millisecond {
		t.Fatalf("publish p99 = %v — the hot path is NOT isolated from the dead broker", p99)
	}
	if sheds == 0 {
		t.Fatal("a full bounded buffer must shed (no shed seen)")
	}
	st := b.Stats()
	if st.Shed == 0 || int(st.Shed) != sheds {
		t.Fatalf("shed counter = %d, want %d (drops are never silent)", st.Shed, sheds)
	}

	closed := make(chan struct{})
	go func() { _ = b.Close(); close(closed) }()
	select {
	case <-closed: // bounded flush: no deadlock on a dead broker
	case <-time.After(10 * time.Second):
		t.Fatal("Close deadlocked against a dead broker")
	}
}

// U-004: a SLOW broker (every produce delayed via kfake's control hook)
// stalls acks, not ingest — Publish p99 stays flat while records batch in
// the bounded buffer and complete asynchronously once the broker responds.
func TestAsyncPublishLatencyIsolatedFromSlowBroker(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.SeedTopics(1, NetworkResultsTopic))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	// Delay every produce request 150ms — far above the asserted publish p99.
	cluster.ControlKey(int16(kmsg.Produce), func(kmsg.Request) (kmsg.Response, error, bool) {
		time.Sleep(150 * time.Millisecond)
		return nil, nil, false // continue normal handling after the delay
	})
	cluster.KeepControl()

	b, err := NewKafka(cluster.ListenAddrs(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	const calls = 50
	lat := make([]time.Duration, 0, calls)
	for i := 0; i < calls; i++ {
		t0 := time.Now()
		if err := b.Publish(context.Background(), NetworkResultsTopic, []byte("t1"), []byte("v")); err != nil {
			t.Fatalf("publish: %v", err)
		}
		lat = append(lat, time.Since(t0))
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p99 := lat[len(lat)*99/100-1]
	if p99 > 100*time.Millisecond {
		t.Fatalf("publish p99 = %v under a 150ms-slow broker — not isolated", p99)
	}

	// The batched records complete asynchronously despite the slow broker.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if st := b.Stats(); st.Produced+st.Failed >= calls {
			if st.Produced == 0 {
				t.Fatalf("no record was acked by the slow broker: %+v", st)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("async completions never landed: %+v", b.Stats())
}
