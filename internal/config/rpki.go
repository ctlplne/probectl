// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import "time"

func loadRPKIConfig(l *loader, cfg *Config) {
	maxInt := int(^uint(0) >> 1)
	cfg.FlowEnrichRPKIFile = l.str("PROBECTL_FLOW_ENRICH_RPKI_FILE", "")
	cfg.FlowEnrichRPKIMaxAge = l.dur("PROBECTL_FLOW_ENRICH_RPKI_MAX_AGE", 2*time.Hour)
	if cfg.FlowEnrichRPKIMaxAge <= 0 {
		l.errf("PROBECTL_FLOW_ENRICH_RPKI_MAX_AGE must be positive")
	}
	cfg.FlowEnrichRPKIMemoryBytes = l.intRange("PROBECTL_FLOW_ENRICH_RPKI_MEMORY_BYTES", 2<<30, 1, maxInt)
	cfg.FlowEnrichRPKIWorkUnits = l.intRange("PROBECTL_FLOW_ENRICH_RPKI_WORK_UNITS", 8<<30, 1, maxInt)
}
