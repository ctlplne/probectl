// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

// Self-observability exposition for the cluster + fairness series the shipped
// Helm PrometheusRule alerts on (RTO-08). These series were previously emitted
// only into probectl's own TSDB via remote-write (internal/cluster and
// internal/fairness WriteSeries), so a ServiceMonitor scrape of /metrics could
// never satisfy ProbectlWritesPaused / ProbectlReplicaLagHigh /
// ProbectlFairnessShedOrRejected. Register them on the registry /metrics serves
// so the alerts can actually fire from a scrape (OPS-005: self-metrics only —
// the /metrics surface carries process-wide aggregates, never tenant labels or
// tenant data, unlike the per-tenant TSDB twins).
//
// The gauges/counters read s.cluster and s.fairnessGate at scrape time, so they
// are registered unconditionally at construction (before WithCluster /
// WithFairness run) and stay correct once those seams are wired; a nil manager
// or gate reports the single-region / no-enforcement default.
func (s *Server) registerSelfObservabilityMetrics() {
	if s == nil || s.metrics == nil {
		return
	}

	// Cluster HA (S-EE2). Single-region (no cluster manager) always has usable
	// writes and no replica to lag, so ProbectlWritesPaused / ProbectlReplicaLagHigh
	// stay quiet there — matching the single-region default the write fence uses.
	s.metrics.Gauge("probectl_cluster_writes_usable",
		"1 when cluster fencing considers config writes usable on this replica, 0 when writes are fenced/paused; single-region deployments report 1. Process-wide, no tenant labels.",
		func() float64 {
			if s.cluster == nil {
				return 1
			}
			if s.cluster.Status().WritesUsable {
				return 1
			}
			return 0
		})
	s.metrics.Gauge("probectl_cluster_replica_lag_seconds",
		"Observed Postgres replica replay lag in seconds; 0 when this replica has no reader/standby to measure (including single-region). Process-wide, no tenant labels.",
		func() float64 {
			if s.cluster == nil {
				return 0
			}
			if r := s.cluster.Status().Reader; r != nil {
				return r.LagSeconds
			}
			return 0
		})

	// Fairness accounting (S-T7). /metrics carries no tenant labels, so expose
	// the process-wide aggregate (summed across every tenant and meter) of the
	// same cumulative counters internal/fairness writes per-tenant into the TSDB.
	s.metrics.CounterFunc("probectl_fairness_shed_units_total",
		"Process-wide fairness-shed units since start, summed across all tenants and ingest meters; no tenant labels.",
		func() float64 {
			if s.fairnessGate == nil {
				return 0
			}
			var total float64
			for _, snap := range s.fairnessGate.SnapshotAll() {
				for _, c := range snap.Ingest {
					total += float64(c.ShedUnits)
				}
			}
			return total
		})
	s.metrics.CounterFunc("probectl_fairness_queries_rejected_total",
		"Process-wide fairness query rejections since start (concurrency + budget guards), summed across all tenants; no tenant labels.",
		func() float64 {
			if s.fairnessGate == nil {
				return 0
			}
			var total float64
			for _, snap := range s.fairnessGate.SnapshotAll() {
				total += float64(snap.Queries.RejectedConcurrency + snap.Queries.RejectedBudget)
			}
			return total
		})
}
