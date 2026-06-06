package pipeline

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// TestConsumerKafkaMode proves bus-mode parity for the result pipeline: the same
// consumer drains results over the real Kafka client (an in-process kfake broker,
// no JVM/Docker) into the TSDB, identical to the memory-mode path.
func TestConsumerKafkaMode(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.SeedTopics(1, bus.NetworkResultsTopic))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()

	b, err := bus.NewKafka(cluster.ListenAddrs(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	w := tsdb.NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = NewConsumer(b, w, "kfake-test", logging.New(io.Discard, "error", "json")).Run(ctx)
		close(done)
	}()
	time.Sleep(500 * time.Millisecond) // let the consumer join the group

	payload, err := proto.Marshal(&resultv1.Result{TenantId: "t1", AgentId: "a1", CanaryType: "noop", Success: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Publish(ctx, bus.NetworkResultsTopic, []byte("t1"), payload); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if len(w.Query("probectl_probe_success", map[string]string{"tenant_id": "t1"})) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done

	if got := w.Query("probectl_probe_success", map[string]string{"tenant_id": "t1"}); len(got) == 0 || got[0].Value != 1 {
		t.Errorf("result not queryable via the Kafka-mode pipeline: %+v", got)
	}
}
