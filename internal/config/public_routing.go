// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"math"
	"time"
)

func loadPublicRoutingConfig(l *loader, cfg *Config) {
	maxInt := int(^uint(0) >> 1)
	cfg.AgentMaxReceiveBytes = l.intRange("PROBECTL_AGENT_MAX_RECEIVE_BYTES", 4<<20, 1, math.MaxInt32)
	cfg.PublicRoutingMemoryBytes = l.intRange("PROBECTL_PUBLIC_ROUTING_MEMORY_BYTES", 2<<30, 1, maxInt)
	cfg.PublicRoutingWorkUnits = l.intRange("PROBECTL_PUBLIC_ROUTING_WORK_UNITS", 2<<30, 1, maxInt)
	cfg.BGPRoutingStateBytes = l.intRange("PROBECTL_BGP_ROUTING_STATE_BYTES", 64<<30, 1, maxInt)
	cfg.BGPRoutingCaptureStateBytes = l.intRange("PROBECTL_BGP_CAPTURE_STATE_BYTES", 64<<30, 1, maxInt)
	cfg.DeviceCounterCaptureStateBytes = l.intRange("PROBECTL_DEVICE_COUNTER_CAPTURE_STATE_BYTES", 64<<30, 1, maxInt)
	cfg.DeviceCounterMemoryBytes = l.intRange("PROBECTL_DEVICE_COUNTER_MEMORY_BYTES", 2<<30, 64<<10, maxInt-1)
	cfg.DeviceCounterWorkUnits = l.intRange("PROBECTL_DEVICE_COUNTER_WORK_UNITS", 4<<30, 64<<10, maxInt-1)
	cfg.DeviceCounterTenantMemoryBytes = l.intRange("PROBECTL_DEVICE_COUNTER_TENANT_MEMORY_BYTES", 1<<30, 1, maxInt-1)
	cfg.DeviceCounterTotalMemoryBytes = l.intRange("PROBECTL_DEVICE_COUNTER_TOTAL_MEMORY_BYTES", 4<<30, 1, maxInt-1)
	if cfg.DeviceCounterTotalMemoryBytes < cfg.DeviceCounterTenantMemoryBytes {
		l.errf("PROBECTL_DEVICE_COUNTER_TOTAL_MEMORY_BYTES: must cover the per-tenant counter memory admission")
	}
	cfg.DeviceCounterTimeout = l.dur("PROBECTL_DEVICE_COUNTER_TIMEOUT", time.Minute)
	if cfg.DeviceCounterTimeout <= 0 || cfg.DeviceCounterTimeout > time.Duration(1<<63-1)/6 {
		l.errf("PROBECTL_DEVICE_COUNTER_TIMEOUT: must be positive and representable")
	}
	cfg.PublicRoutingMaxAge = l.dur("PROBECTL_PUBLIC_ROUTING_MAX_AGE", 12*time.Hour)
	if cfg.PublicRoutingMaxAge <= 0 {
		l.errf("PROBECTL_PUBLIC_ROUTING_MAX_AGE: must be positive")
	}
}
