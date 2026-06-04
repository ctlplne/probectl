package agent

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/canary"
	"github.com/imfeelingtheagi/probectl/internal/logging"
)

func TestHostProbesIntoBuffer(t *testing.T) {
	buf, err := OpenBuffer(t.TempDir(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	noop, err := canary.NewNoop(canary.Config{Type: "noop", Target: "t"})
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{
		scheduled: []scheduled{{canary: noop, interval: 5 * time.Millisecond}},
		buffer:    buf,
		tenantID:  "tenant-1",
		agentID:   "agent-1",
		log:       logging.New(io.Discard, "error", "json"),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.Run(ctx); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && buf.Len() < 3 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	if buf.Len() < 1 {
		t.Fatalf("expected the no-op to buffer results, got %d", buf.Len())
	}
	frames, err := buf.PeekAll()
	if err != nil {
		t.Fatal(err)
	}
	var env resultEnvelope
	if err := json.Unmarshal(frames[0], &env); err != nil {
		t.Fatal(err)
	}
	if env.TenantID != "tenant-1" || env.AgentID != "agent-1" || env.Result.Type != "noop" || !env.Result.Success {
		t.Errorf("buffered envelope = %+v", env)
	}
}
