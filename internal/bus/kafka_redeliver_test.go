// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bus

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"
)

// TestKafkaCommitNeverAdvancesPastAFailedHandler is the end-to-end regression
// for ING-12 on the Kafka transport, driven through the REAL Kafka.Subscribe
// against an in-process broker (kfake) — no live cluster required.
//
// The defect: franz-go's MarkCommitRecords moves a partition's committed head to
// max(current, offset+1), so marking a LATER successful record advances the
// committed offset PAST an earlier record whose handler errored — silently
// skipping it (telemetry loss). The old consumer marked each successful record
// the instant it was processed, so one success after a failure buried the
// failure.
//
// The test publishes three records to a single partition. A first consumer
// session fails the handler for "a" and succeeds for "b" and "c". It then stops,
// which commits whatever was marked. A second session in the same group resumes
// from the committed offset: "a" was never successfully handled, so a correct
// commit must NOT have advanced past it, and "a" must be redelivered. Under the
// bug the later successes committed past "a", the second session starts beyond
// it, and "a" is gone.
func TestKafkaCommitNeverAdvancesPastAFailedHandler(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.SeedTopics(1, NetworkResultsTopic)) // one partition: a,b,c share it, in order
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()

	b, err := NewKafka(cluster.ListenAddrs(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const group = "ing12-kafka-group"
	key := []byte("tenant-x")
	want := []string{"a", "b", "c"}
	for _, v := range want {
		if err := b.Publish(ctx, NetworkResultsTopic, key, []byte(v)); err != nil {
			t.Fatalf("publish %s: %v", v, err)
		}
	}
	if err := b.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// Session 1: the handler refuses "a" (always) and accepts "b" and "c".
	s1ctx, s1cancel := context.WithCancel(ctx)
	var mu sync.Mutex
	s1seen := map[string]int{}
	s1sawAll := make(chan struct{})
	s1returned := make(chan struct{})
	go func() {
		defer close(s1returned)
		_ = b.Subscribe(s1ctx, NetworkResultsTopic, group, func(_ context.Context, m Message) error {
			v := string(m.Value)
			mu.Lock()
			s1seen[v]++
			distinct := len(s1seen)
			mu.Unlock()
			if distinct == len(want) {
				select {
				case <-s1sawAll:
				default:
					close(s1sawAll)
				}
			}
			if v == "a" {
				return errors.New("handler refuses 'a'")
			}
			return nil
		})
	}()

	select {
	case <-s1sawAll:
	case <-time.After(30 * time.Second):
		mu.Lock()
		seen := s1seen
		mu.Unlock()
		t.Fatalf("session 1 never saw all three records: %v", seen)
	}

	// Stop session 1 and wait for Subscribe to return. Returning means the client
	// closed, which synchronously commits the marked offsets — so the second
	// session sees the committed position this session actually produced.
	s1cancel()
	select {
	case <-s1returned:
	case <-time.After(20 * time.Second):
		t.Fatal("session 1 Subscribe did not return after its context was canceled")
	}

	// Session 2: same group, resumes from the committed offset.
	s2ctx, s2cancel := context.WithCancel(ctx)
	defer s2cancel()
	gotA := make(chan struct{})
	go func() {
		_ = b.Subscribe(s2ctx, NetworkResultsTopic, group, func(_ context.Context, m Message) error {
			if string(m.Value) == "a" {
				select {
				case <-gotA:
				default:
					close(gotA)
				}
			}
			return nil
		})
	}()

	select {
	case <-gotA:
		// "a" was redelivered: the commit was held at/before it, not advanced past.
	case <-time.After(30 * time.Second):
		t.Fatal("record 'a' whose handler errored was never redelivered — it was silently committed past (ING-12)")
	}
}
