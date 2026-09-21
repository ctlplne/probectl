// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/fairness"
)

// newFairnessGate is the single production construction path for per-tenant
// fairness. Long-running serve and standalone MCP stdio must use the same
// deployment defaults, stored tenant overrides, and idle-state bound.
func newFairnessGate(cfg *config.Config, pool *pgxpool.Pool) *fairness.Gate {
	var source fairness.PolicySource
	if pool != nil {
		source = fairness.NewPGStore(pool)
	}
	return fairness.NewGate(fairness.Policy{
		ResultsPerSec:       cfg.FairnessResultsPerSec,
		FlowEventsPerSec:    cfg.FairnessFlowEventsPerSec,
		IngestBytesPerSec:   cfg.FairnessIngestBytesPerSec,
		DeviceMetricsPerSec: cfg.FairnessDeviceMetricsPerSec,
		OTLPSeriesPerSec:    cfg.FairnessOTLPSeriesPerSec,
		BurstSeconds:        cfg.FairnessBurstSeconds,
		QueryConcurrency:    cfg.FairnessQueryConcurrency,
		QueriesPerMin:       cfg.FairnessQueriesPerMin,
	}, source).WithIdleTTL(cfg.FairnessTenantIdleTTL)
}
