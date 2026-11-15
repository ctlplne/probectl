// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPublishedServiceRangeConfigKeepsRaiseableOfflineAdmission(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil || cfg.FlowEnrichServiceFile != "" || cfg.FlowEnrichServiceMaxAge != 24*time.Hour || cfg.FlowEnrichServiceMemoryBytes != 256<<20 {
		t.Fatal("service range defaults lost complete offline admission", err)
	}
	cfg, err = Load(envFunc(map[string]string{"PROBECTL_FLOW_ENRICH_SERVICE_FILE": "/private/operator/ranges.json", "PROBECTL_FLOW_ENRICH_SERVICE_MAX_AGE": "72h", "PROBECTL_FLOW_ENRICH_SERVICE_MEMORY_BYTES": "8589934592"}))
	if err != nil || cfg.FlowEnrichServiceMaxAge != 72*time.Hour || cfg.FlowEnrichServiceMemoryBytes != 8<<30 || cfg.FlowEnrichASN || cfg.FlowEnrichIXP {
		t.Fatal("source admission was clamped or enabled remote lookups", err)
	}
	for _, value := range []string{fmt.Sprint(cfg.LogValue()), fmt.Sprint(cfg.Redacted())} {
		if !strings.Contains(value, "flow_enrich_service") || strings.Contains(value, "/private/operator") {
			t.Fatal("source admission is hidden or path leaked", value)
		}
	}
	for _, key := range []string{"PROBECTL_FLOW_ENRICH_SERVICE_MAX_AGE", "PROBECTL_FLOW_ENRICH_SERVICE_MEMORY_BYTES"} {
		for _, invalid := range []string{"0", "-1", "invalid"} {
			if _, err := Load(envFunc(map[string]string{key: invalid})); err == nil {
				t.Fatal("invalid service source admission accepted", key, invalid)
			}
		}
	}
}
