// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import "time"

func loadServiceRangeConfig(l *loader, cfg *Config) {
	cfg.FlowEnrichServiceFile = l.str("PROBECTL_FLOW_ENRICH_SERVICE_FILE", "")
	cfg.FlowEnrichServiceMaxAge = l.dur("PROBECTL_FLOW_ENRICH_SERVICE_MAX_AGE", 24*time.Hour)
	if cfg.FlowEnrichServiceMaxAge <= 0 {
		l.errf("PROBECTL_FLOW_ENRICH_SERVICE_MAX_AGE must be positive")
	}
	cfg.FlowEnrichServiceMemoryBytes = l.intRange("PROBECTL_FLOW_ENRICH_SERVICE_MEMORY_BYTES", 256<<20, 1, int(^uint(0)>>1))
}
