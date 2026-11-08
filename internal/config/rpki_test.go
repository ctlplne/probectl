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

func TestRPKILocalConfigKeepsCompleteRaiseableAdmissionAndNoEgress(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil || cfg.FlowEnrichRPKIFile != "" || cfg.FlowEnrichRPKIMaxAge != 2*time.Hour || cfg.FlowEnrichRPKIMemoryBytes != 2<<30 || cfg.FlowEnrichRPKIWorkUnits != 8<<30 {
		t.Fatal("RPKI source defaults lost finite complete-file admission", err)
	}
	cfg, err = Load(envFunc(map[string]string{"PROBECTL_FLOW_ENRICH_RPKI_FILE": "/operator-private/vrps.json", "PROBECTL_FLOW_ENRICH_RPKI_MAX_AGE": "48h", "PROBECTL_FLOW_ENRICH_RPKI_MEMORY_BYTES": "8589934592", "PROBECTL_FLOW_ENRICH_RPKI_WORK_UNITS": "34359738368"}))
	if err != nil || cfg.FlowEnrichRPKIMaxAge != 48*time.Hour || cfg.FlowEnrichRPKIMemoryBytes != 8<<30 || cfg.FlowEnrichRPKIWorkUnits != 32<<30 || cfg.FlowEnrichASN || cfg.FlowEnrichIXP {
		t.Fatal("local validator source clamped approved admission or enabled outbound lookups", err)
	}
	logged := fmt.Sprint(cfg.LogValue())
	if !strings.Contains(logged, "flow_enrich_rpki") || strings.Contains(logged, "/operator-private/") {
		t.Fatal("RPKI admission was hidden or local path leaked", logged)
	}
	for _, key := range []string{"PROBECTL_FLOW_ENRICH_RPKI_MAX_AGE", "PROBECTL_FLOW_ENRICH_RPKI_MEMORY_BYTES", "PROBECTL_FLOW_ENRICH_RPKI_WORK_UNITS"} {
		for _, invalid := range []string{"0", "-1", "invalid"} {
			if _, err := Load(envFunc(map[string]string{key: invalid})); err == nil {
				t.Fatal("unavailable RPKI admission was accepted", key, invalid)
			}
		}
	}
}
