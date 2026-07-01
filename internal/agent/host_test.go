// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/canary"
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
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
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

type failedResultCanary struct{}

func (failedResultCanary) Describe() canary.Spec {
	return canary.Spec{Type: "udp", Version: "test", Description: "failed result fixture"}
}

func (failedResultCanary) Run(context.Context) (canary.Result, error) {
	start := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	return canary.Result{
		Type: "udp", Target: "127.0.0.1:0", StartedAt: start,
		Duration: time.Millisecond, Success: false, Error: "udp: dial 127.0.0.1:0: invalid argument",
		Attributes: map[string]string{"network.transport": "udp"},
	}, nil
}

func TestHostProbeEnqueuesFailedResultEnvelope(t *testing.T) {
	buf, err := OpenBuffer(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{
		buffer:   buf,
		tenantID: "tenant-a",
		agentID:  "agent-a",
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	h.probe(context.Background(), failedResultCanary{})

	frames, err := buf.PeekAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("buffered frames = %d, want 1", len(frames))
	}
	var env resultEnvelope
	if err := json.Unmarshal(frames[0], &env); err != nil {
		t.Fatal(err)
	}
	if env.TenantID != "tenant-a" || env.AgentID != "agent-a" || env.ResultID == "" {
		t.Fatalf("identity envelope = %+v", env)
	}
	if env.Result.Success || env.Result.Error == "" || env.Result.Type != "udp" {
		t.Fatalf("failed canary result was not preserved: %+v", env.Result)
	}
}
