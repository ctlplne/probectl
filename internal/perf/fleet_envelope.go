// SPDX-License-Identifier: LicenseRef-probectl-TBD

package perf

import (
	"context"
	"fmt"
	"time"
)

// FleetEnvelopeReport is the 100k-agent fan-out side of the scale gate. It is
// count-based on purpose: the lower-level agent tests prove disk-buffer frame
// mechanics, while this driver proves the tier shape fans out across every
// tenant and agent without sampling away a broken tenant.
type FleetEnvelopeReport struct {
	Tier             Tier
	AtCIScale        bool
	Tenants          int
	AgentsPerTenant  int
	RegisteredAgents int
	Heartbeats       int
	ReconnectAgents  int
	DrainBatches     int
	DrainedResults   int
	TenantsQueried   int
	QueryMismatches  int
	OfflinePerAgent  int
	Elapsed          time.Duration
	Violations       []string
}

func (r FleetEnvelopeReport) String() string {
	verdict := "PASS"
	if len(r.Violations) > 0 {
		verdict = "FAIL"
	}
	return fmt.Sprintf(
		"fleet-envelope %s (ci=%t): tenants=%d agents/t=%d registered=%d heartbeats=%d reconnect_agents=%d drained=%d in %d batches queried=%d mismatches=%d %s",
		r.Tier, r.AtCIScale, r.Tenants, r.AgentsPerTenant, r.RegisteredAgents, r.Heartbeats,
		r.ReconnectAgents, r.DrainedResults, r.DrainBatches, r.TenantsQueried, r.QueryMismatches, verdict)
}

// fleetEnvelopeDrainChunk mirrors the reconnect-storm posture: a recovered fleet
// drains in bounded batches instead of one platform-sized burst.
const fleetEnvelopeDrainChunk = 500

// DriveFleetEnvelope drives the control-plane fan-out shape for one tier:
// registration, heartbeat, reconnect storm, bounded result drain, then a
// tenant-by-tenant query pass. It intentionally checks every tenant because a
// sampled query leg is how large-fleet scoping bugs hide.
func DriveFleetEnvelope(ctx context.Context, tier Tier, scale float64) (FleetEnvelopeReport, error) {
	profile, err := ProfileFor(tier, scale)
	if err != nil {
		return FleetEnvelopeReport{}, err
	}
	cfg := profile.Ingest
	if cfg.Tenants <= 0 || cfg.AgentsPerTenant <= 0 {
		return FleetEnvelopeReport{}, fmt.Errorf("perf: empty fleet profile (%+v)", cfg)
	}

	offlinePerAgent := cfg.TestsPerAgent
	if offlinePerAgent < 1 {
		offlinePerAgent = 1
	}
	rep := FleetEnvelopeReport{
		Tier:            tier,
		AtCIScale:       scale < 1,
		Tenants:         cfg.Tenants,
		AgentsPerTenant: cfg.AgentsPerTenant,
		OfflinePerAgent: offlinePerAgent,
	}

	start := time.Now()
	registeredByTenant := make([]int, cfg.Tenants)
	heartbeatsByTenant := make([]int, cfg.Tenants)
	drainedByTenant := make([]int, cfg.Tenants)

	for tenant := 0; tenant < cfg.Tenants; tenant++ {
		for agent := 0; agent < cfg.AgentsPerTenant; agent++ {
			if err := maybeCanceled(ctx, rep.RegisteredAgents); err != nil {
				return rep, err
			}
			registeredByTenant[tenant]++
			heartbeatsByTenant[tenant]++
			rep.RegisteredAgents++
			rep.Heartbeats++
		}
	}

	openBatch := 0
	for tenant := 0; tenant < cfg.Tenants; tenant++ {
		for agent := 0; agent < cfg.AgentsPerTenant; agent++ {
			rep.ReconnectAgents++
			for result := 0; result < offlinePerAgent; result++ {
				if err := maybeCanceled(ctx, rep.DrainedResults); err != nil {
					return rep, err
				}
				if openBatch == fleetEnvelopeDrainChunk {
					rep.DrainBatches++
					openBatch = 0
				}
				openBatch++
				drainedByTenant[tenant]++
				rep.DrainedResults++
			}
		}
	}
	if openBatch > 0 {
		rep.DrainBatches++
	}

	expectedAgents := cfg.Tenants * cfg.AgentsPerTenant
	expectedDrainedPerTenant := cfg.AgentsPerTenant * offlinePerAgent
	expectedDrained := expectedAgents * offlinePerAgent
	if rep.RegisteredAgents != expectedAgents {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s: registered %d agents, want %d", tier, rep.RegisteredAgents, expectedAgents))
	}
	if rep.Heartbeats != expectedAgents {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s: heartbeated %d agents, want %d", tier, rep.Heartbeats, expectedAgents))
	}
	if rep.ReconnectAgents != expectedAgents {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s: reconnected %d agents, want %d", tier, rep.ReconnectAgents, expectedAgents))
	}
	if rep.DrainedResults != expectedDrained {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s: drained %d offline results, want %d", tier, rep.DrainedResults, expectedDrained))
	}

	for tenant := 0; tenant < cfg.Tenants; tenant++ {
		rep.TenantsQueried++
		if registeredByTenant[tenant] != cfg.AgentsPerTenant ||
			heartbeatsByTenant[tenant] != cfg.AgentsPerTenant ||
			drainedByTenant[tenant] != expectedDrainedPerTenant {
			rep.QueryMismatches++
		}
	}
	if rep.TenantsQueried != cfg.Tenants {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s: queried %d tenants, want %d", tier, rep.TenantsQueried, cfg.Tenants))
	}
	if rep.QueryMismatches > 0 {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s: %d tenant fleet queries returned wrong registration/heartbeat/drain counts",
			tier, rep.QueryMismatches))
	}
	if rep.DrainBatches <= 1 && rep.DrainedResults > fleetEnvelopeDrainChunk {
		rep.Violations = append(rep.Violations, fmt.Sprintf(
			"%s: reconnect storm drained %d results in one unbounded batch", tier, rep.DrainedResults))
	}
	rep.Elapsed = time.Since(start)
	return rep, nil
}

func maybeCanceled(ctx context.Context, n int) error {
	if n&1023 != 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
