// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"testing"
	"time"
)

func TestIXMembershipLocalConfigKeepsNoEgressAndIndependentPositiveFreshness(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil || cfg.FlowEnrichIXMembershipFile != "" || cfg.FlowEnrichIXMembershipMaxAge != 24*time.Hour {
		t.Fatal("membership source default changed", err)
	}
	cfg, err = Load(envFunc(map[string]string{"PROBECTL_FLOW_ENRICH_IX_MEMBERSHIP_FILE": "/data/netixlan.json", "PROBECTL_FLOW_ENRICH_IX_MEMBERSHIP_MAX_AGE": "48h"}))
	if err != nil || cfg.FlowEnrichIXMembershipFile != "/data/netixlan.json" || cfg.FlowEnrichIXMembershipMaxAge != 48*time.Hour || cfg.FlowEnrichASN || cfg.FlowEnrichIXP || cfg.FlowEnrichIXPrefixFile != "" {
		t.Fatal("local membership source enabled unrelated data or egress", err)
	}
	for _, invalid := range []string{"0", "-1h", "invalid"} {
		if _, err := Load(envFunc(map[string]string{"PROBECTL_FLOW_ENRICH_IX_MEMBERSHIP_MAX_AGE": invalid})); err == nil {
			t.Fatal("membership cache accepted unavailable freshness", invalid)
		}
	}
}
