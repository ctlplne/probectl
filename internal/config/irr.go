// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import "time"

func loadIRRConfig(l *loader, cfg *Config) {
	maxInt := int(^uint(0) >> 1)
	cfg.FlowEnrichIRRManifest = l.str("PROBECTL_FLOW_ENRICH_IRR_MANIFEST", "")
	cfg.FlowEnrichIRRMaxAge = l.dur("PROBECTL_FLOW_ENRICH_IRR_MAX_AGE", 48*time.Hour)
	cfg.FlowEnrichIRRReviewAge = l.dur("PROBECTL_FLOW_ENRICH_IRR_REVIEW_AGE", 365*24*time.Hour)
	if cfg.FlowEnrichIRRMaxAge <= 0 || cfg.FlowEnrichIRRReviewAge <= 0 {
		l.errf("IRR snapshot and object review ages must be positive")
	}
	cfg.FlowEnrichIRRMemoryBytes = l.intRange("PROBECTL_FLOW_ENRICH_IRR_MEMORY_BYTES", 1<<30, 128<<10, maxInt)
	cfg.FlowEnrichIRRWorkUnits = l.intRange("PROBECTL_FLOW_ENRICH_IRR_WORK_UNITS", 8<<30, 128<<10, maxInt)
}
