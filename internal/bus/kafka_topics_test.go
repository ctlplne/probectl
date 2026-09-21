// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bus

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"
)

// TestKafkaEnsureTopicsCreatesMissingLanesOnce (DPR-047): against a broker
// with no topics and no auto-creation, the plane creates what is missing,
// reports it, is idempotent, and can then publish and flush.
func TestKafkaEnsureTopicsCreatesMissingLanesOnce(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.SeedTopics(1, "probectl.pre-existing"))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	b, err := NewKafka(cluster.ListenAddrs(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	want := []string{NetworkResultsTopic, "probectl.t-acme.network.results", "probectl.pre-existing"}
	missing, err := b.TopicsMissing(ctx, want)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(missing, ",") != NetworkResultsTopic+",probectl.t-acme.network.results" {
		t.Fatalf("missing = %v", missing)
	}
	created, err := b.EnsureTopics(ctx, want, 2, -1)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if strings.Join(created, ",") != NetworkResultsTopic+",probectl.t-acme.network.results" {
		t.Fatalf("created = %v", created)
	}
	if missing, err = b.TopicsMissing(ctx, want); err != nil || len(missing) != 0 {
		t.Fatalf("after ensure: missing=%v err=%v", missing, err)
	}
	if created, err = b.EnsureTopics(ctx, want, 2, -1); err != nil || len(created) != 0 {
		t.Fatalf("second ensure must create nothing: created=%v err=%v", created, err)
	}
	if err := b.Publish(ctx, "probectl.t-acme.network.results", []byte("k"), []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := b.Flush(ctx); err != nil {
		t.Fatalf("flush after ensure: %v", err)
	}
}

// TestKafkaFlushErrorNamesTheLastProduceFailure keeps "context deadline
// exceeded" from being the whole story: the broker's reason rides along.
func TestKafkaFlushErrorNamesTheLastProduceFailure(t *testing.T) {
	k := &Kafka{}
	if got := k.flushError(nil); got != nil {
		t.Fatalf("nil stays nil, got %v", got)
	}
	base := errors.New("context deadline exceeded")
	if got := k.flushError(base); got != base {
		t.Fatalf("no failure recorded: error must pass through unchanged, got %v", got)
	}
	k.recordFailure("probectl.network.results", errors.New("UNKNOWN_TOPIC_OR_PARTITION"))
	got := k.flushError(base)
	if !errors.Is(got, base) || !strings.Contains(got.Error(), "probectl.network.results") || !strings.Contains(got.Error(), "UNKNOWN_TOPIC_OR_PARTITION") {
		t.Fatalf("decorated error = %v", got)
	}
}
