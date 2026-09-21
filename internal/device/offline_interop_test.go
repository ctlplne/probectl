// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"os"
	"testing"
)

func TestOfflineInteropSNMPSimReplayNormalizesMetrics(t *testing.T) {
	if _, err := os.ReadFile("../../test/interop/fixtures/device-telemetry.json"); err != nil {
		t.Fatal(err)
	}
	conn := &ipWalkConn{fakeConn: healthyConn(), ipRows: map[string]uint32{"10.0.0.1": 1}}
	ms, inv, err := pollSNMP(conn, Target{Address: "192.0.2.1", Transport: TransportSNMPv2c, Sensors: true}, "tenant-a", "device-agent-1", pollTime)
	if err != nil {
		t.Fatal(err)
	}
	if inv.SysName != "core-sw1" || len(ms) == 0 {
		t.Fatalf("snmpsim replay inventory=%+v metrics=%d", inv, len(ms))
	}
	for _, m := range ms {
		if m.TenantID != "tenant-a" || m.AgentID != "device-agent-1" || m.Source != SourceSNMP {
			t.Fatalf("SNMP metric not normalized/stamped: %+v", m)
		}
	}
}

func TestOfflineInteropGNMIcReplayNormalizesMetrics(t *testing.T) {
	if _, err := os.ReadFile("../../test/interop/fixtures/device-telemetry.json"); err != nil {
		t.Fatal(err)
	}
	TestGNMITLSCollectorAgainstMockTarget(t)
}
