// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package remediation

import (
	"context"
	"testing"
	"time"

	rem "github.com/imfeelingtheagi/probectl/internal/remediation"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

// TestEstimatorReadOnlyWhatIf proves the estimator sizes the blast radius via a
// READ-ONLY topology simulation: a known target yields a dry-run; an unknown
// target (or no store) fails closed with an unknown radius that blocks approval.
func TestEstimatorReadOnlyWhatIf(t *testing.T) {
	s := topology.NewMemoryStore()
	now := time.Now()
	s.ObservePath("t1", topology.PathInput{
		AgentID: "a1", Target: "web", TargetIP: "203.0.113.10",
		Hops: []string{"10.0.0.1", "10.0.0.2"},
	}, now)
	s.ObserveServiceEdge("t1", topology.ServiceEdgeInput{
		Source: "web-svc", Destination: "api", DestPort: 8080, Transport: "tcp",
	}, now)

	est := NewTopologyEstimator(s, nil)

	// A known element: the simulation runs and returns a (non-negative) radius.
	dry := est.Estimate(context.Background(), "t1", "hop:10.0.0.1")
	if dry.BlastRadius < 0 || dry.Note == noteUnknown {
		t.Fatalf("known target should simulate, got %+v", dry)
	}

	// An unknown element: Simulate errors → fail closed (unknown radius).
	dry = est.Estimate(context.Background(), "t1", "hop:does-not-exist")
	if dry.BlastRadius != -1 || dry.Note != noteUnknown {
		t.Fatalf("unknown target must fail closed, got %+v", dry)
	}

	// No store at all: fail closed.
	if d := NewTopologyEstimator(nil, nil).Estimate(context.Background(), "t1", "hop:10.0.0.1"); d.BlastRadius != -1 {
		t.Fatalf("nil store must fail closed, got %+v", d)
	}
}

// TestMemStoreEdgeCases covers the not-found and already-decided paths of the
// in-memory store.
func TestMemStoreEdgeCases(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()

	if _, err := m.Get(ctx, testTenant, "nope"); err == nil {
		t.Fatal("Get missing must error")
	}
	if _, err := m.Decide(ctx, testTenant, "nope", rem.StateApproved, "u", "", time.Now()); err == nil {
		t.Fatal("Decide missing must error")
	}

	p, _ := m.Insert(ctx, testTenant, rem.Proposal{State: rem.StateProposed, CreatedAt: time.Now()})
	if _, err := m.Decide(ctx, testTenant, p.ID, rem.StateApproved, "u", "ok", time.Now()); err != nil {
		t.Fatalf("first decide: %v", err)
	}
	// A second decide on the now-approved row fails (not proposed).
	if _, err := m.Decide(ctx, testTenant, p.ID, rem.StateRejected, "u", "", time.Now()); err != rem.ErrNotProposed {
		t.Fatalf("second decide: err=%v, want ErrNotProposed", err)
	}
}
