// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package canary_test

import (
	"context"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/canary"
)

// TestA2ALoopback proves the two-way measurement core: a responder echoes the
// initiator's probes and the initiator reports round-trip plus forward + reverse
// one-way metrics (both directions), for UDP and TCP.
func TestA2ALoopback(t *testing.T) {
	for _, mode := range []string{"udp", "tcp"} {
		t.Run(mode, func(t *testing.T) {
			sessionID := "loopback-" + mode
			resp, err := canary.StartA2AResponder(mode, "127.0.0.1", sessionID)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan canary.Result, 1)
			go func() { done <- resp.Serve(ctx, 4, "agent-B") }()

			res, err := canary.RunA2AInitiator(context.Background(), mode, resp.Addr(), 4, 2*time.Second, "agent-B", sessionID)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Success || res.Metrics["loss.ratio"] != 0 || res.Metrics["packets.received"] != 4 {
				t.Fatalf("initiator: success=%v metrics=%v", res.Success, res.Metrics)
			}
			for _, k := range []string{"rtt.avg.ms", "forward.avg.ms", "reverse.avg.ms"} {
				if _, ok := res.Metrics[k]; !ok {
					t.Errorf("initiator missing %s: %v", k, res.Metrics)
				}
			}

			cancel()
			rr := <-done
			if rr.Metrics["packets.received"] != 4 || rr.Metrics["loss.ratio"] != 0 {
				t.Errorf("responder: %v", rr.Metrics)
			}
		})
	}
}

func TestA2ALoopbackRejectsWrongSessionKey(t *testing.T) {
	for _, mode := range []string{"udp", "tcp"} {
		t.Run(mode, func(t *testing.T) {
			resp, err := canary.StartA2AResponder(mode, "127.0.0.1", "good-session-"+mode)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan canary.Result, 1)
			go func() { done <- resp.Serve(ctx, 1, "agent-B") }()

			res, err := canary.RunA2AInitiator(context.Background(), mode, resp.Addr(), 1, 150*time.Millisecond, "agent-B", "wrong-session-"+mode)
			if err != nil {
				t.Fatal(err)
			}
			if res.Success || res.Metrics["packets.received"] != 0 {
				t.Fatalf("wrong-session initiator got an authenticated echo: success=%v metrics=%v", res.Success, res.Metrics)
			}

			cancel()
			rr := <-done
			if rr.Metrics["packets.received"] != 0 {
				t.Fatalf("responder counted an unauthenticated probe: %v", rr.Metrics)
			}
		})
	}
}
