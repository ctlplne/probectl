package canary

import (
	"context"
	"time"
)

// noop is a canary that always succeeds immediately. It exercises the agent
// runtime (scheduling, buffering, forwarding) without touching the network.
type noop struct {
	cfg Config
}

// NewNoop builds a no-op canary.
func NewNoop(cfg Config) (Canary, error) {
	return &noop{cfg: cfg}, nil
}

// Describe returns the no-op spec.
func (n *noop) Describe() Spec {
	return Spec{Type: "noop", Version: "1", Description: "no-op canary used to exercise the agent runtime"}
}

// Run returns an immediate successful result.
func (n *noop) Run(_ context.Context) (Result, error) {
	start := time.Now()
	return Result{
		Type:      "noop",
		Target:    n.cfg.Target,
		Success:   true,
		StartedAt: start,
		Duration:  time.Since(start),
		Metrics:   map[string]float64{},
	}, nil
}
