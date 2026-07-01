// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
)

// TestDeadLetterReplayReingests is the ARCH-001 acceptance test: a record
// parked on probectl.deadletter.results is, after a replay, re-published to the
// source topic (probectl.network.results) with its ORIGINAL tenant key and
// payload — proving the product can recover dead-lettered telemetry itself.
func TestDeadLetterReplayReingests(t *testing.T) {
	b := bus.NewMemory()
	defer b.Close()

	// A subscriber on the SOURCE topic captures what the replay re-ingests.
	type got struct {
		key, val []byte
	}
	captured := make(chan got, 4)
	srcCtx, srcCancel := context.WithCancel(context.Background())
	defer srcCancel()
	var srcWG sync.WaitGroup
	srcWG.Add(1)
	go func() {
		defer srcWG.Done()
		_ = b.Subscribe(srcCtx, bus.NetworkResultsTopic, "test-source", func(_ context.Context, m bus.Message) error {
			captured <- got{key: m.Key, val: m.Value}
			return nil
		})
	}()

	// Start the replayer draining the DLQ topic.
	r := NewDeadLetterReplayer(b, testLogger())
	replayDone := make(chan ReplayResult, 1)
	go func() {
		res, err := r.Replay(context.Background(), ReplayConfig{
			DLQTopic:    bus.DeadLetterResultsTopic,
			IdleTimeout: 300 * time.Millisecond,
		})
		if err != nil {
			t.Errorf("replay: %v", err)
		}
		replayDone <- res
	}()

	// Give both subscribers a moment to register, then dead-letter a record.
	time.Sleep(50 * time.Millisecond)
	origKey := []byte("tenant-a")
	origVal := []byte("the-original-result-bytes")
	if err := b.Publish(context.Background(), bus.DeadLetterResultsTopic, origKey, origVal); err != nil {
		t.Fatal(err)
	}

	// The record must reappear on the source topic, verbatim.
	select {
	case g := <-captured:
		if string(g.key) != "tenant-a" {
			t.Errorf("replayed key = %q, want tenant-a (original tenant must be preserved)", g.key)
		}
		if string(g.val) != "the-original-result-bytes" {
			t.Errorf("replayed payload = %q, want the original bytes", g.val)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out: replay did not re-ingest the dead-lettered record onto the source topic")
	}

	// The replayer terminates on idle and reports the count.
	select {
	case res := <-replayDone:
		if res.Replayed != 1 {
			t.Errorf("replayed count = %d, want 1", res.Replayed)
		}
		if res.SourceTopic != bus.NetworkResultsTopic {
			t.Errorf("source topic = %q, want %q", res.SourceTopic, bus.NetworkResultsTopic)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("replay did not terminate on idle")
	}
}

// TestDeadLetterReplayRejectsUnknownTopic: a non-DLQ topic fails closed.
func TestDeadLetterReplayRejectsUnknownTopic(t *testing.T) {
	r := NewDeadLetterReplayer(bus.NewMemory(), testLogger())
	if _, err := r.Replay(context.Background(), ReplayConfig{DLQTopic: "probectl.network.results"}); err == nil {
		t.Fatal("replay must reject a topic that is not a dead-letter topic")
	}
}

// TestReplaySourceMapping pins every DLQ topic to its source.
func TestReplaySourceMapping(t *testing.T) {
	cases := map[string]string{
		bus.DeadLetterBGPTopic:         bus.BGPEventsTopic,
		bus.DeadLetterResultsTopic:     bus.NetworkResultsTopic,
		bus.DeadLetterDeviceTopic:      bus.DeviceMetricsTopic,
		bus.DeadLetterFlowTopic:        bus.FlowEventsTopic,
		bus.DeadLetterOTLPMetricsTopic: bus.OTLPMetricsTopic,
		bus.DeadLetterOTLPTracesTopic:  bus.OTLPTracesTopic,
		bus.DeadLetterOTLPLogsTopic:    bus.OTLPLogsTopic,
	}
	for dlq, want := range cases {
		got, ok := SourceTopicFor(dlq)
		if !ok || got != want {
			t.Errorf("SourceTopicFor(%q) = %q,%v; want %q", dlq, got, ok, want)
		}
	}
}

func TestReplayableTopicsIncludesBGP(t *testing.T) {
	for _, topic := range ReplayableTopics() {
		if topic == bus.DeadLetterBGPTopic {
			return
		}
	}
	t.Fatalf("ReplayableTopics() missing %q", bus.DeadLetterBGPTopic)
}
