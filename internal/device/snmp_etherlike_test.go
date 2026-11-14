// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"testing"

	"github.com/gosnmp/gosnmp"
	"google.golang.org/protobuf/proto"

	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
)

func TestSNMPEtherLikeOriginalCountersReachTenantBoundWire(t *testing.T) {
	var keys [2][32]byte
	for lane, tenant := range []string{"11111111-1111-4111-8111-111111111111", "66666666-6666-4666-8666-666666666666"} {
		conn := counterClockFixture()
		// Independently authored RFC 3635 columns: a mixed-speed device exposes
		// HC only on port1 and Counter32 on port2. The fallback also advertises
		// a different port1 value, which must not replace its observed HC word.
		conn.tables[".1.3.6.1.2.1.10.7.11.1.2"] = map[uint32]gosnmp.SnmpPDU{1: {Type: gosnmp.Counter64, Value: uint64(1<<53 + 1)}}
		conn.tables[".1.3.6.1.2.1.10.7.11.1.1"] = map[uint32]gosnmp.SnmpPDU{1: {Type: gosnmp.Counter64, Value: ^uint64(0)}}
		conn.tables[".1.3.6.1.2.1.10.7.2.1.3"] = map[uint32]gosnmp.SnmpPDU{1: {Type: gosnmp.Counter32, Value: uint32(9)}, 2: {Type: gosnmp.Counter32, Value: uint32(1<<32 - 1)}}
		conn.tables[".1.3.6.1.2.1.10.7.2.1.2"] = map[uint32]gosnmp.SnmpPDU{1: {Type: gosnmp.Counter32, Value: uint32(8)}, 2: {Type: gosnmp.Counter32, Value: uint32(0)}}
		metrics, _, err := pollSNMP(t.Context(), conn, Target{Address: "192.0.2.9", Transport: TransportSNMPv2c}, tenant, "same-agent", pollTime)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []struct {
			name, iface string
			value       uint64
			width       uint32
		}{
			{"probectl.device.if.in.fcs.errors", "eth0", 1<<53 + 1, 64},
			{"probectl.device.if.in.alignment.errors", "eth0", ^uint64(0), 64},
			{"probectl.device.if.in.fcs.errors", "eth1", 1<<32 - 1, 32},
			{"probectl.device.if.in.alignment.errors", "eth1", 0, 32},
		} {
			got := find(t, metrics, want.name, want.iface)
			counter := got.ExactCounter
			if got.TenantID != tenant || got.AgentID != "same-agent" || got.Unit != "packets" || counter == nil || counter.Value != want.value || counter.Width != want.width || !counter.UptimeKnown || !counter.DiscontinuityKnown || !counter.PollStartedAt.Equal(pollTime) {
				t.Fatalf("EtherLike original counter lost typed value, source or continuity: %+v %+v", got, counter)
			}
		}
		wire := &devicev1.DeviceMetricBatch{}
		for _, metric := range metrics {
			if metric.ExactCounter != nil {
				wire.Metrics = append(wire.Metrics, metric.ToProto())
			}
		}
		raw, err := proto.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseCounterBatch(t.Context(), tenant, raw, 8<<20, 8<<20)
		if err != nil || len(parsed.Metrics) != 8 || parsed.Input.PointCount != 8 {
			t.Fatal("complete mixed IF-MIB/EtherLike poll did not reach the original counter lane", err)
		}
		keys[lane] = parsed.Digest
	}
	if keys[0] == keys[1] {
		t.Fatal("paired collectors lost their distinct tenant-bound original bytes")
	}
	metrics, _, err := pollSNMP(t.Context(), counterClockFixture(), Target{Address: "192.0.2.9", Transport: TransportSNMPv2c}, "unsupported", "same-agent", pollTime)
	if err != nil {
		t.Fatal(err)
	}
	for _, metric := range metrics {
		if metric.Name == "probectl.device.if.in.fcs.errors" || metric.Name == "probectl.device.if.in.alignment.errors" {
			t.Fatal("unsupported optional EtherLike object became a zero observation")
		}
	}
}
