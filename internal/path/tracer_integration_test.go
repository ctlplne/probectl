//go:build integration

package path

import (
	"context"
	"testing"
	"time"
)

// TestRunLoopback proves the tracer end to end against a reachable destination: a
// trace to loopback resolves, probes, parses the Echo Reply, and merges into a
// Path with the destination as a hop node. Full multi-hop ECMP/MPLS discovery
// needs raw sockets (privileged) and is covered by the merge/parse fixtures; this
// test runs on the unprivileged datagram socket and skips if even that is
// restricted.
func TestRunLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := Config{Target: "127.0.0.1", Mode: "icmp", TraceCount: 2, MaxHops: 5, PerHopTimeout: time.Second}
	p, err := Run(ctx, cfg)
	if err != nil {
		t.Skipf("path trace unavailable (sockets restricted): %v", err)
	}
	if p.TargetIP != "127.0.0.1" {
		t.Errorf("target ip = %q, want 127.0.0.1", p.TargetIP)
	}
	if p.TraceCount != 2 {
		t.Errorf("trace count = %d, want 2", p.TraceCount)
	}
	if !p.DestinationReached {
		t.Fatalf("loopback destination not reached: %+v", p)
	}
	found := false
	for _, h := range p.Hops {
		for _, n := range h.Nodes {
			if n.IP == "127.0.0.1" {
				found = true
				if n.Received == 0 {
					t.Errorf("destination node has no responses: %+v", n)
				}
			}
		}
	}
	if !found {
		t.Errorf("destination is not a hop node: %+v", p.Hops)
	}
}
