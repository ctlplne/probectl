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
	if cfg.AgentMaxReceiveBytes != 16<<20 || cfg.PublicRoutingMemoryBytes != 2<<30 || cfg.PublicRoutingWorkUnits != 2<<30 || cfg.BGPRoutingStateBytes != 64<<30 || cfg.BGPRoutingCaptureStateBytes != 64<<30 || cfg.PublicRoutingMaxAge != 12*time.Hour || cfg.AgentTransportEnabled() {
		t.Fatal("public routing changed finite defaults or enabled an unsolicited listener")
	}
	values := map[string]string{"PROBECTL_AGENT_MAX_RECEIVE_BYTES": "8388608", "PROBECTL_PUBLIC_ROUTING_MEMORY_BYTES": "8589934592", "PROBECTL_PUBLIC_ROUTING_WORK_UNITS": "8589934592", "PROBECTL_BGP_ROUTING_STATE_BYTES": "1099511627776", "PROBECTL_BGP_CAPTURE_STATE_BYTES": "2199023255552", "PROBECTL_PUBLIC_ROUTING_MAX_AGE": "24h"}
	raised, err := Load(envFunc(values))
	if err != nil || raised.AgentMaxReceiveBytes != 8<<20 || raised.PublicRoutingMemoryBytes != 8<<30 || raised.PublicRoutingWorkUnits != 8<<30 || raised.BGPRoutingStateBytes != 1<<40 || raised.BGPRoutingCaptureStateBytes != 2<<40 || raised.PublicRoutingMaxAge != 24*time.Hour {
		t.Fatal("complete source operation admission was clamped", err)
	}
	seen := map[string]bool{}
	for _, attribute := range raised.LogValue().Group() {
		seen[attribute.Key] = true
	}
	for _, key := range []string{"agent_max_receive_bytes", "public_routing_memory_bytes", "public_routing_work_units", "bgp_routing_state_bytes", "bgp_routing_capture_state_bytes", "public_routing_max_age"} {
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

func TestDeviceCounterHistoryAdmissionIsRaiseableAndTenantFair(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DeviceCounterMemoryBytes != 2<<30 || cfg.DeviceCounterWorkUnits != 4<<30 || cfg.DeviceCounterTimeout != time.Minute || cfg.DeviceCounterTenantMemoryBytes != 1<<30 || cfg.DeviceCounterTotalMemoryBytes != 4<<30 {
		t.Fatal("counter history lost finite defaults")
	}
	values := map[string]string{"PROBECTL_DEVICE_COUNTER_MEMORY_BYTES": "1099511627776", "PROBECTL_DEVICE_COUNTER_WORK_UNITS": "2199023255552", "PROBECTL_DEVICE_COUNTER_TENANT_MEMORY_BYTES": "1099511627776", "PROBECTL_DEVICE_COUNTER_TOTAL_MEMORY_BYTES": "2199023255552", "PROBECTL_DEVICE_COUNTER_TIMEOUT": "10m"}
	raised, err := Load(envFunc(values))
	if err != nil || raised.DeviceCounterMemoryBytes != 1<<40 || raised.DeviceCounterWorkUnits != 2<<40 || raised.DeviceCounterTenantMemoryBytes != 1<<40 || raised.DeviceCounterTotalMemoryBytes != 2<<40 || raised.DeviceCounterTimeout != 10*time.Minute {
		t.Fatal("complete counter workload resources were clamped", err)
	}
	seen := map[string]bool{}
	for _, attribute := range raised.LogValue().Group() {
		seen[attribute.Key] = true
	}
	for _, key := range []string{"device_counter_memory_bytes", "device_counter_work_units", "device_counter_timeout", "device_counter_tenant_memory_bytes", "device_counter_total_memory_bytes"} {
		if !seen[key] {
			t.Fatal("counter resource policy is not observable", key)
		}
	}
	for _, values := range []map[string]string{{"PROBECTL_DEVICE_COUNTER_MEMORY_BYTES": "0"}, {"PROBECTL_DEVICE_COUNTER_WORK_UNITS": "-1"}, {"PROBECTL_DEVICE_COUNTER_TIMEOUT": "0s"}, {"PROBECTL_DEVICE_COUNTER_TOTAL_MEMORY_BYTES": "1"}} {
		if _, err := Load(envFunc(values)); err == nil {
			t.Fatal("invalid or unfair counter resources reached startup", values)
		}
	}
}
