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

func TestPublicRoutingAdmissionIsFiniteRaiseableObservableAndOffline(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentMaxReceiveBytes != 4<<20 || cfg.PublicRoutingMemoryBytes != 512<<20 || cfg.PublicRoutingWorkUnits != 2<<30 || cfg.BGPRoutingStateBytes != 64<<30 || cfg.PublicRoutingMaxAge != 12*time.Hour || cfg.AgentTransportEnabled() {
		t.Fatal("public routing changed finite defaults or enabled an unsolicited listener")
	}
	values := map[string]string{"PROBECTL_AGENT_MAX_RECEIVE_BYTES": "8388608", "PROBECTL_PUBLIC_ROUTING_MEMORY_BYTES": "2147483648", "PROBECTL_PUBLIC_ROUTING_WORK_UNITS": "8589934592", "PROBECTL_BGP_ROUTING_STATE_BYTES": "1099511627776", "PROBECTL_PUBLIC_ROUTING_MAX_AGE": "24h"}
	raised, err := Load(envFunc(values))
	if err != nil || raised.AgentMaxReceiveBytes != 8<<20 || raised.PublicRoutingMemoryBytes != 2<<30 || raised.PublicRoutingWorkUnits != 8<<30 || raised.BGPRoutingStateBytes != 1<<40 || raised.PublicRoutingMaxAge != 24*time.Hour {
		t.Fatal("complete source operation admission was clamped", err)
	}
	seen := map[string]bool{}
	for _, attribute := range raised.LogValue().Group() {
		seen[attribute.Key] = true
	}
	for _, key := range []string{"agent_max_receive_bytes", "public_routing_memory_bytes", "public_routing_work_units", "bgp_routing_state_bytes", "public_routing_max_age"} {
		if !seen[key] {
			t.Fatal("public source admission is not observable", key)
		}
	}
	for key := range values {
		for _, invalid := range []string{"0", "-1", "invalid", "9999999999999999999999999999"} {
			if _, err := Load(envFunc(map[string]string{key: invalid})); err == nil {
				t.Fatal("unbounded or invalid public source policy reached startup", key, invalid)
			}
		}
	}
}
