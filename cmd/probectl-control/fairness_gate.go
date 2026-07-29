// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
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
