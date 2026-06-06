// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package remediation

import (
	"context"
	"time"

	rem "github.com/imfeelingtheagi/probectl/internal/remediation"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

// TopologyEstimator computes a proposal's blast radius via the S43 topology
// what-if (topology.Simulate). It is READ-ONLY and executes nothing — it fails
// an element in a copy of the graph and counts the affected entities. An
// unknown target (or no topology) yields an "unknown" dry-run, which the
// service treats conservatively (blocks approval, fail closed).
type TopologyEstimator struct {
	store topology.Store
	slo   topology.SLOSource // optional (SLO impact); nil is fine
}

// NewTopologyEstimator wraps the topology store.
func NewTopologyEstimator(store topology.Store, slo topology.SLOSource) *TopologyEstimator {
	return &TopologyEstimator{store: store, slo: slo}
}

// Estimate runs the what-if and returns the dry-run. Blast radius = the count
// of impacted services + prefixes + newly-disconnected hosts.
func (e *TopologyEstimator) Estimate(_ context.Context, tenantID, target string) rem.DryRun {
	if e == nil || e.store == nil {
		return rem.DryRun{BlastRadius: -1, Note: noteUnknown}
	}
	impact, err := topology.Simulate(e.store, tenantID, target, time.Time{}, e.slo)
	if err != nil {
		// Unknown target / no graph: fail closed (blast radius unknown).
		return rem.DryRun{BlastRadius: -1, Note: noteUnknown}
	}
	return rem.DryRun{
		BlastRadius:      len(impact.ImpactedServices) + len(impact.ImpactedPrefixes) + len(impact.Disconnected),
		ImpactedServices: impact.ImpactedServices,
		ImpactedPrefixes: impact.ImpactedPrefixes,
		Disconnected:     impact.Disconnected,
	}
}
